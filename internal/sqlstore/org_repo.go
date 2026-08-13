package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

type OrgRepository struct {
	db *DB
}

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

func (r *OrgRepository) Create(ctx context.Context, org *domain.Organization) error {
	_, err := r.db.ExecContext(ctx, orgCreateQuery,
		org.ID, org.Name, org.Slug, org.CreatedBy, org.OwnerCount, org.MemberCount,
		"{}", org.CreatedAt, org.UpdatedAt)
	return err
}

func (r *OrgRepository) GetByID(ctx context.Context, id string) (*domain.Organization, error) {
	o, err := scanOrg(r.db.QueryRowContext(ctx, orgByIDQuery, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

func (r *OrgRepository) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	o, err := scanOrg(r.db.QueryRowContext(ctx, orgBySlugQuery, slug))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

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

func (r *OrgRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, orgDeleteQuery, id)
	return err
}

func (r *OrgRepository) AddMember(ctx context.Context, member *domain.OrgMember) error {
	_, err := r.db.ExecContext(ctx, orgAddMemberQuery,
		member.OrgID, member.UserID, string(member.Role), member.JoinedAt)
	return err
}

func (r *OrgRepository) RemoveMember(ctx context.Context, orgID, userID string) error {
	_, err := r.db.ExecContext(ctx, orgRemoveMemberQuery, orgID, userID)
	return err
}

func (r *OrgRepository) UpdateMemberRole(ctx context.Context, orgID, userID string, role domain.OrgRole) error {
	_, err := r.db.ExecContext(ctx, orgUpdateMemberRoleQuery, string(role), orgID, userID)
	return err
}

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

func (r *OrgRepository) ListMembers(ctx context.Context, orgID string, offset, limit int) ([]domain.OrgMemberDetail, int, error) {
	var total int
	err := r.db.QueryRowContext(ctx, orgListMembersCountQuery, orgID).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := r.db.QueryContext(ctx, orgListMembersQuery, orgID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var members []domain.OrgMemberDetail
	for rows.Next() {
		var md domain.OrgMemberDetail
		u := &domain.User{}
		if err := rows.Scan(
			&md.OrgID, &md.UserID, &md.Role, &md.JoinedAt,
			&u.ID, &u.Email, &u.Name, &u.Role, &u.IsVerified, &u.IsBanned, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, 0, err
		}
		md.User = u
		members = append(members, md)
	}
	if members == nil {
		members = []domain.OrgMemberDetail{}
	}
	return members, total, rows.Err()
}

func (r *OrgRepository) ListUserOrgs(ctx context.Context, userID string) ([]domain.Organization, error) {
	rows, err := r.db.QueryContext(ctx, orgListUserOrgsQuery, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var orgs []domain.Organization
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, err
		}
		orgs = append(orgs, *o)
	}
	if orgs == nil {
		orgs = []domain.Organization{}
	}
	return orgs, rows.Err()
}

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

func (r *OrgRepository) DecrementUserOrgOwnerCount(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, orgDecrementUserOwnerCountQuery, userID)
	return err
}

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

func (r *OrgRepository) DecrementOrgMemberCount(ctx context.Context, orgID string) error {
	_, err := r.db.ExecContext(ctx, orgDecrementOrgMemberCountQuery, orgID)
	return err
}

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

func (r *OrgRepository) IncrementOrgOwnerCount(ctx context.Context, orgID string) error {
	_, err := r.db.ExecContext(ctx, orgIncrementOrgOwnerCountQuery, orgID)
	return err
}

func (r *OrgRepository) DecrementOwnerCountForOrgOwners(ctx context.Context, orgID string) error {
	_, err := r.db.ExecContext(ctx, orgDecrementOwnerCountForOrgOwnersQuery, orgID)
	return err
}

type OrgInviteRepository struct {
	db *DB
}

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

func (r *OrgInviteRepository) Create(ctx context.Context, invite *domain.OrgInvite) error {
	_, err := r.db.ExecContext(ctx, orgInviteCreateQuery,
		invite.ID, invite.OrgID, invite.Email, string(invite.Role), invite.CodeHash,
		invite.InvitedBy, invite.ExpiresAt, invite.CreatedAt)
	return err
}

func (r *OrgInviteRepository) GetByID(ctx context.Context, id string) (*domain.OrgInvite, error) {
	i, err := scanOrgInvite(r.db.QueryRowContext(ctx, orgInviteByIDQuery, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return i, err
}

func (r *OrgInviteRepository) GetByCodeHash(ctx context.Context, codeHash string) (*domain.OrgInvite, error) {
	i, err := scanOrgInvite(r.db.QueryRowContext(ctx, orgInviteByCodeHashQuery, codeHash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return i, err
}

func (r *OrgInviteRepository) ListByOrgID(ctx context.Context, orgID string) ([]domain.OrgInvite, error) {
	rows, err := r.db.QueryContext(ctx, orgInviteListByOrgIDQuery, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []domain.OrgInvite
	for rows.Next() {
		i, err := scanOrgInvite(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, *i)
	}
	if invites == nil {
		invites = []domain.OrgInvite{}
	}
	return invites, rows.Err()
}

func (r *OrgInviteRepository) Update(ctx context.Context, invite *domain.OrgInvite) error {
	_, err := r.db.ExecContext(ctx, orgInviteUpdateQuery,
		invite.CodeHash, invite.ExpiresAt, invite.ID)
	return err
}

func (r *OrgInviteRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, orgInviteDeleteQuery, id)
	return err
}

func (r *OrgInviteRepository) ClaimInvite(ctx context.Context, id string) (bool, error) {
	res, err := r.db.ExecContext(ctx, orgInviteClaimQuery, id, time.Now().UTC())
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
}
