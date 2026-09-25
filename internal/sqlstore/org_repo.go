package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

var _ port.OrgRepository = (*OrgRepository)(nil)

// orgMemberOrderByWhitelist and orgOrderByWhitelist map caller-supplied
// OrderBy strings to the real (table-qualified) SQL column they're allowed
// to sort by. An unrecognized OrderBy falls back to the map's zero value
// being handled by the caller (see ListMembers/ListUserOrgs) rather than
// ever reaching raw SQL — column names can't be bind parameters, so this
// whitelist-then-substitute is the injection guard, exactly like
// orderByWhitelist in user_repo.go.
//
// Sorting members by "role" orders alphabetically (admin < member < owner)
// since role is a plain string column — NOT by OrgRole.Weight() seniority.
var orgMemberOrderByWhitelist = map[string]string{
	"joined_at": "om.joined_at",
	"role":      "om.role",
	"name":      "u.name",
	"email":     "u.email",
}

var orgOrderByWhitelist = map[string]string{
	"name":         "o.name",
	"created_at":   "o.created_at",
	"member_count": "o.member_count",
}

var orgInviteOrderByWhitelist = map[string]string{
	"created_at": "created_at",
	"expires_at": "expires_at",
	"email":      "email",
	"role":       "role",
}

// OrgRepository stores organizations and their memberships.
type OrgRepository struct {
	db *DB
}

// NewOrgRepository returns an organization repository.
func NewOrgRepository(db *DB) *OrgRepository {
	return &OrgRepository{db: db}
}

func scanOrg(sc interface{ Scan(dest ...any) error }) (*domain.Organization, error) {
	o := &domain.Organization{}
	var createdBy sql.NullString
	var metadata sql.NullString
	if err := sc.Scan(
		&o.ID, &o.Name, &o.Slug, &createdBy, &o.OwnerCount, &o.MemberCount,
		&metadata, &o.CreatedAt, &o.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if createdBy.Valid {
		o.CreatedBy = &createdBy.String
	}
	if metadata.Valid && metadata.String != "" {
		o.Metadata = parseJSONMap(metadata.String)
	}
	if o.Metadata == nil {
		o.Metadata = make(map[string]interface{})
	}
	return o, nil
}

func parseJSONMap(s string) map[string]interface{} {
	if s == "{}" || s == "" {
		return make(map[string]interface{})
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return make(map[string]interface{})
	}
	return m
}

// Create stores an organization.
func (r *OrgRepository) Create(ctx context.Context, org *domain.Organization) error {
	_, err := r.db.ExecContext(ctx, orgCreateQuery,
		org.ID, org.Name, org.Slug, org.CreatedBy, org.OwnerCount, org.MemberCount,
		"{}", org.CreatedAt, org.UpdatedAt)
	return wrapCreateErr(r.db.Driver(), err)
}

// GetByID returns an organization by ID or nil when absent.
func (r *OrgRepository) GetByID(ctx context.Context, id string) (*domain.Organization, error) {
	o, err := scanOrg(r.db.QueryRowContext(ctx, orgByIDQuery, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

// GetBySlug returns an organization by slug or nil when absent.
func (r *OrgRepository) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	o, err := scanOrg(r.db.QueryRowContext(ctx, orgBySlugQuery, slug))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

// Update changes an organization's stored values.
func (r *OrgRepository) Update(ctx context.Context, org *domain.Organization) error {
	metadata := "{}"
	if org.Metadata != nil {
		b, err := json.Marshal(org.Metadata)
		if err == nil {
			metadata = string(b)
		}
	}
	_, err := r.db.ExecContext(ctx, orgUpdateQuery,
		org.Name, org.Slug, metadata, org.UpdatedAt, org.ID)
	return err
}

// Delete removes an organization by ID.
func (r *OrgRepository) Delete(ctx context.Context, id string) (bool, error) {
	return affected(r.db.ExecContext(ctx, orgDeleteQuery, id))
}

// AddMember adds a user to an organization.
func (r *OrgRepository) AddMember(ctx context.Context, member *domain.OrgMember) error {
	_, err := r.db.ExecContext(ctx, orgAddMemberQuery,
		member.OrgID, member.UserID, string(member.Role), member.JoinedAt)
	return wrapCreateErr(r.db.Driver(), err)
}

// RemoveMember removes a member when the current role matches.
func (r *OrgRepository) RemoveMember(ctx context.Context, orgID, userID string, expectRole domain.OrgRole) (bool, error) {
	return affected(r.db.ExecContext(ctx, orgRemoveMemberQuery, orgID, userID, string(expectRole)))
}

// UpdateMemberRole changes a member's role when the current role matches.
func (r *OrgRepository) UpdateMemberRole(ctx context.Context, orgID, userID string, expectRole, newRole domain.OrgRole) (bool, error) {
	return affected(r.db.ExecContext(ctx, orgUpdateMemberRoleQuery, string(newRole), orgID, userID, string(expectRole)))
}

// GetMembership returns a user's organization membership or nil when absent.
func (r *OrgRepository) GetMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error) {
	m := &domain.OrgMember{}
	err := r.db.QueryRowContext(ctx, orgGetMembershipQuery, orgID, userID).Scan(
		&m.OrgID, &m.UserID, &m.Role, &m.JoinedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (r *OrgRepository) membersWhere(orgID string, filter port.OrgMemberFilter) (string, []any) {
	where := []string{"om.org_id = $1"}
	args := []any{orgID}
	argIdx := 2

	if filter.Role != nil {
		where = append(where, fmt.Sprintf("om.role = $%d", argIdx))
		args = append(args, string(*filter.Role))
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		searchTerm := "%" + *filter.Search + "%"
		op := "ILIKE"
		if r.db.UsesPositionalParams() {
			op = "LIKE"
		}
		where = append(where, fmt.Sprintf("(u.name %s $%d OR u.email %s $%d)", op, argIdx, op, argIdx+1))
		args = append(args, searchTerm, searchTerm)
	}
	return strings.Join(where, " AND "), args
}

// CountMembers returns how many members of orgID match filter.
func (r *OrgRepository) CountMembers(ctx context.Context, orgID string, filter port.OrgMemberFilter) (int, error) {
	whereClause, args := r.membersWhere(orgID, filter)
	var total int
	q := fmt.Sprintf(`SELECT COUNT(*) FROM organization_members om
		JOIN users u ON u.id = om.user_id WHERE %s`, whereClause)
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// ListMembers returns organization members matching the filter.
func (r *OrgRepository) ListMembers(ctx context.Context, orgID string, filter port.OrgMemberFilter) ([]domain.OrgMemberDetail, error) {
	whereClause, args := r.membersWhere(orgID, filter)
	argIdx := len(args) + 1

	orderCol := orgMemberOrderByWhitelist[string(filter.OrderBy)]
	if orderCol == "" {
		orderCol = "om.joined_at"
	}
	orderDir := "DESC"
	if filter.OrderDirection == api.SortAscending {
		orderDir = "ASC"
	}

	base := fmt.Sprintf(`
		SELECT %s
		FROM organization_members om
		JOIN users u ON u.id = om.user_id
		WHERE %s ORDER BY %s %s`, orgMemberSelectCols, whereClause, orderCol, orderDir)

	query := base
	if filter.Limit > 0 {
		query = fmt.Sprintf("%s LIMIT $%d OFFSET $%d", base, argIdx, argIdx+1)
		args = append(args, filter.Limit, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	members := []domain.OrgMemberDetail{}
	for rows.Next() {
		var md domain.OrgMemberDetail
		u := &domain.User{}
		if err := rows.Scan(
			&md.OrgID, &md.UserID, &md.Role, &md.JoinedAt,
			&u.ID, &u.Email, &u.Name, &u.Role, &u.IsVerified, &u.IsBanned, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			_ = rows.Close()
			return nil, err
		}
		md.User = u
		members = append(members, md)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("organization members list close: %w", err)
	}
	return members, nil
}

func (r *OrgRepository) userOrgsWhere(userID string, search *string, role *domain.OrgRole) (string, []any) {
	where := []string{"om.user_id = $1"}
	args := []any{userID}
	argIdx := 2

	if role != nil && *role != "" {
		where = append(where, fmt.Sprintf("om.role = $%d", argIdx))
		args = append(args, string(*role))
		argIdx++
	}

	if search != nil && *search != "" {
		searchTerm := "%" + *search + "%"
		op := "ILIKE"
		if r.db.UsesPositionalParams() {
			op = "LIKE"
		}
		where = append(where, fmt.Sprintf("(o.name %s $%d OR o.slug %s $%d)", op, argIdx, op, argIdx+1))
		args = append(args, searchTerm, searchTerm)
	}
	return strings.Join(where, " AND "), args
}

// CountUserOrgs returns how many orgs the user belongs to that match search/role.
func (r *OrgRepository) CountUserOrgs(ctx context.Context, userID string, filter port.UserOrgFilter) (int, error) {
	whereClause, args := r.userOrgsWhere(userID, filter.Search, filter.Role)
	var total int
	q := fmt.Sprintf(`SELECT COUNT(*) FROM organizations o
		JOIN organization_members om ON om.org_id = o.id WHERE %s`, whereClause)
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// ListUserOrgs returns a user's organizations matching the filter.
func (r *OrgRepository) ListUserOrgs(ctx context.Context, userID string, filter port.UserOrgFilter) ([]domain.Organization, error) {
	whereClause, args := r.userOrgsWhere(userID, filter.Search, filter.Role)
	argIdx := len(args) + 1

	orderCol := orgOrderByWhitelist[string(filter.OrderBy)]
	if orderCol == "" {
		orderCol = "o.name"
	}
	orderDir := "DESC"
	if filter.OrderDirection == api.SortAscending {
		orderDir = "ASC"
	}

	base := fmt.Sprintf(`
		SELECT %s
		FROM organizations o
		JOIN organization_members om ON om.org_id = o.id
		WHERE %s ORDER BY %s %s`, orgSelectColsAliased, whereClause, orderCol, orderDir)

	query := base
	if filter.Limit > 0 {
		query = fmt.Sprintf("%s LIMIT $%d OFFSET $%d", base, argIdx, argIdx+1)
		args = append(args, filter.Limit, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	orgs := []domain.Organization{}
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		orgs = append(orgs, *o)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("user organizations list close: %w", err)
	}
	return orgs, nil
}

// List returns every organization matching filter — the platform-admin,
// cross-org listing. Unlike ListUserOrgs, there is no organization_members
// join: this queries organizations directly.
func (r *OrgRepository) buildListWhere(filter port.OrgFilter) (string, []any) {
	where := []string{"1=1"}
	args := []any{}
	argIdx := 1

	if filter.Search != nil && *filter.Search != "" {
		searchTerm := "%" + *filter.Search + "%"
		op := "ILIKE"
		if r.db.UsesPositionalParams() {
			op = "LIKE"
		}
		where = append(where, fmt.Sprintf("(o.name %s $%d OR o.slug %s $%d)", op, argIdx, op, argIdx+1))
		args = append(args, searchTerm, searchTerm)
		argIdx += 2
	}
	if filter.CreatedAfter != nil {
		where = append(where, fmt.Sprintf("o.created_at > $%d", argIdx))
		args = append(args, *filter.CreatedAfter)
		argIdx++
	}
	if filter.CreatedBefore != nil {
		where = append(where, fmt.Sprintf("o.created_at < $%d", argIdx))
		args = append(args, *filter.CreatedBefore)
	}
	return strings.Join(where, " AND "), args
}

// Count returns how many organizations match filter (Offset/Limit ignored).
func (r *OrgRepository) Count(ctx context.Context, filter port.OrgFilter) (int, error) {
	whereClause, args := r.buildListWhere(filter)
	var total int
	q := fmt.Sprintf(`SELECT COUNT(*) FROM organizations o WHERE %s`, whereClause)
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// List returns organizations matching the filter.
func (r *OrgRepository) List(ctx context.Context, filter port.OrgFilter) ([]domain.Organization, error) {
	whereClause, args := r.buildListWhere(filter)
	argIdx := len(args) + 1

	orderCol := orgOrderByWhitelist[string(filter.OrderBy)]
	if orderCol == "" {
		orderCol = "o.name"
	}
	orderDir := "DESC"
	if filter.OrderDirection == api.SortAscending {
		orderDir = "ASC"
	}

	base := fmt.Sprintf(`
		SELECT %s
		FROM organizations o
		WHERE %s ORDER BY %s %s`, orgSelectColsAliased, whereClause, orderCol, orderDir)

	query := base
	if filter.Limit > 0 {
		query = fmt.Sprintf("%s LIMIT $%d OFFSET $%d", base, argIdx, argIdx+1)
		args = append(args, filter.Limit, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	orgs := []domain.Organization{}
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		orgs = append(orgs, *o)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("organizations list close: %w", err)
	}
	return orgs, nil
}

// IncrementUserOrgOwnerCount increments a user's owned organization count within the limit.
func (r *OrgRepository) IncrementUserOrgOwnerCount(ctx context.Context, userID string, maxOrgs int) error {
	res, err := r.db.ExecContext(ctx, orgIncrementOwnerCountQuery, userID, maxOrgs)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrOrgLimitReached
	}
	return nil
}

// DecrementUserOrgOwnerCount decrements a user's owned organization count.
func (r *OrgRepository) DecrementUserOrgOwnerCount(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, orgDecrementUserOwnerCountQuery, userID)
	return err
}

// IncrementOrgMemberCount increments an organization's member count within the limit.
func (r *OrgRepository) IncrementOrgMemberCount(ctx context.Context, orgID string, maxMembers int) error {
	res, err := r.db.ExecContext(ctx, orgIncrementOrgMemberCountQuery, orgID, maxMembers)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrOrgMemberLimitReached
	}
	return nil
}

// DecrementOrgMemberCount decrements an organization's member count.
func (r *OrgRepository) DecrementOrgMemberCount(ctx context.Context, orgID string) error {
	_, err := r.db.ExecContext(ctx, orgDecrementOrgMemberCountQuery, orgID)
	return err
}

// TryDecrementOrgOwnerCount decrements the owner count unless it would remove the last owner.
func (r *OrgRepository) TryDecrementOrgOwnerCount(ctx context.Context, orgID string) error {
	res, err := r.db.ExecContext(ctx, orgTryDecrementOwnerCountQuery, orgID)
	if err != nil {
		return err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrCannotRemoveLastOwner
	}
	return nil
}

// IncrementOrgOwnerCount increments an organization's owner count.
func (r *OrgRepository) IncrementOrgOwnerCount(ctx context.Context, orgID string) error {
	_, err := r.db.ExecContext(ctx, orgIncrementOrgOwnerCountQuery, orgID)
	return err
}

// ListUserMemberships returns every (org, role) pair the user is a member
// of. Used by account deletion to walk and unwind all memberships inside
// one transaction.
func (r *OrgRepository) ListUserMemberships(ctx context.Context, userID string) ([]port.AccountOrgMembership, error) {
	rows, err := r.db.QueryContext(ctx, orgUserMembershipsQuery, userID)
	if err != nil {
		return nil, err
	}
	var out []port.AccountOrgMembership
	for rows.Next() {
		var m port.AccountOrgMembership
		var role string
		if err := rows.Scan(&m.OrgID, &role); err != nil {
			_ = rows.Close()
			return nil, err
		}
		m.Role = domain.OrgRole(role)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("user organization memberships close: %w", err)
	}
	return out, nil
}

// DecrementOwnerCountForOrgOwners decrements the owner count for each owner of an organization.
func (r *OrgRepository) DecrementOwnerCountForOrgOwners(ctx context.Context, orgID string) error {
	_, err := r.db.ExecContext(ctx, orgDecrementOwnerCountForOrgOwnersQuery, orgID)
	return err
}

// OrgInviteRepository stores organization invitations.
type OrgInviteRepository struct {
	db *DB
}

// NewOrgInviteRepository returns an organization invite repository.
func NewOrgInviteRepository(db *DB) *OrgInviteRepository {
	return &OrgInviteRepository{db: db}
}

func scanOrgInvite(sc interface{ Scan(dest ...any) error }) (*domain.OrgInvite, error) {
	i := &domain.OrgInvite{}
	if err := sc.Scan(&i.ID, &i.OrgID, &i.Email, &i.Role, &i.CodeHash, &i.InvitedBy, &i.ExpiresAt, &i.CreatedAt); err != nil {
		return nil, err
	}
	return i, nil
}

// Create stores an organization invitation.
func (r *OrgInviteRepository) Create(ctx context.Context, invite *domain.OrgInvite) error {
	_, err := r.db.ExecContext(ctx, orgInviteCreateQuery,
		invite.ID, invite.OrgID, invite.Email, string(invite.Role), invite.CodeHash,
		invite.InvitedBy, invite.ExpiresAt, invite.CreatedAt)
	return err
}

// GetByID returns an organization invitation by ID or nil when absent.
func (r *OrgInviteRepository) GetByID(ctx context.Context, id string) (*domain.OrgInvite, error) {
	i, err := scanOrgInvite(r.db.QueryRowContext(ctx, orgInviteByIDQuery, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return i, err
}

// GetByCodeHash returns an organization invitation by code hash or nil when absent.
func (r *OrgInviteRepository) GetByCodeHash(ctx context.Context, codeHash string) (*domain.OrgInvite, error) {
	i, err := scanOrgInvite(r.db.QueryRowContext(ctx, orgInviteByCodeHashQuery, codeHash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return i, err
}

// orgInvitesWhere builds the " ... " predicate (always starting "org_id = $1")
// and args shared by ListByOrgID and CountByOrgID.
func (r *OrgInviteRepository) orgInvitesWhere(orgID string, filter port.OrgInviteFilter) (string, []any) {
	where := []string{"org_id = $1"}
	args := []any{orgID}
	argIdx := 2

	if filter.Role != nil {
		where = append(where, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, string(*filter.Role))
		argIdx++
	}
	if filter.Status != nil {
		now := time.Now().UTC()
		if *filter.Status == "expired" {
			where = append(where, fmt.Sprintf("expires_at <= $%d", argIdx))
		} else {
			where = append(where, fmt.Sprintf("expires_at > $%d", argIdx))
		}
		args = append(args, now)
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		searchTerm := "%" + *filter.Search + "%"
		op := "ILIKE"
		if r.db.UsesPositionalParams() {
			op = "LIKE"
		}
		// Single column (email) — no reused-placeholder risk here. If a
		// second search column is ever added, give each OR branch its own
		// placeholder (see the identical comment in OrgRepository.ListMembers)
		// rather than reusing one — DB.Rebind rewrites every textual "$N" to
		// "?" positionally for mysql/sqlite, so a reused placeholder silently
		// desyncs args from the generated "?" count on those drivers.
		where = append(where, fmt.Sprintf("email %s $%d", op, argIdx))
		args = append(args, searchTerm)
	}
	return strings.Join(where, " AND "), args
}

// CountByOrgID returns how many of orgID's invites match filter (Offset/Limit
// on filter are ignored).
func (r *OrgInviteRepository) CountByOrgID(ctx context.Context, orgID string, filter port.OrgInviteFilter) (int, error) {
	whereClause, args := r.orgInvitesWhere(orgID, filter)
	var total int
	q := fmt.Sprintf("SELECT COUNT(*) FROM organization_invites WHERE %s", whereClause)
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// ListByOrgID returns an organization's invitations matching the filter.
func (r *OrgInviteRepository) ListByOrgID(ctx context.Context, orgID string, filter port.OrgInviteFilter) ([]domain.OrgInvite, error) {
	whereClause, args := r.orgInvitesWhere(orgID, filter)
	argIdx := len(args) + 1

	orderCol := orgInviteOrderByWhitelist[string(filter.OrderBy)]
	if orderCol == "" {
		orderCol = "created_at"
	}
	orderDir := "DESC"
	if filter.OrderDirection == api.SortAscending {
		orderDir = "ASC"
	}

	base := fmt.Sprintf("SELECT %s FROM organization_invites WHERE %s ORDER BY %s %s", orgInviteCols, whereClause, orderCol, orderDir)

	query := base
	if filter.Limit > 0 {
		query = fmt.Sprintf("%s LIMIT $%d OFFSET $%d", base, argIdx, argIdx+1)
		args = append(args, filter.Limit, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	invites := []domain.OrgInvite{}
	for rows.Next() {
		i, err := scanOrgInvite(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		invites = append(invites, *i)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("organization invite list close: %w", err)
	}
	return invites, nil
}

// Update changes an organization invitation's code hash and expiry.
func (r *OrgInviteRepository) Update(ctx context.Context, invite *domain.OrgInvite) error {
	_, err := r.db.ExecContext(ctx, orgInviteUpdateQuery,
		invite.CodeHash, invite.ExpiresAt, invite.ID)
	return err
}

// Delete removes an organization invitation by ID.
func (r *OrgInviteRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, orgInviteDeleteQuery, id)
	return err
}

// ClaimInvite consumes a matching unexpired organization invitation.
func (r *OrgInviteRepository) ClaimInvite(ctx context.Context, id, codeHash string) (bool, error) {
	res, err := r.db.ExecContext(ctx, orgInviteClaimQuery, id, codeHash, time.Now().UTC())
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}
