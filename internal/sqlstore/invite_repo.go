package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type InviteRepository struct {
	db *DB
}

func NewInviteRepository(db *DB) *InviteRepository {
	return &InviteRepository{db: db}
}

var inviteOrderByWhitelist = map[string]string{
	"created_at": "created_at",
	"expires_at": "expires_at",
	"email":      "email",
	"status":     "status",
}

func (r *InviteRepository) Create(ctx context.Context, invite *domain.Invite) error {
	_, err := r.db.ExecContext(ctx, inviteCreateQuery,
		invite.ID, invite.Email, invite.Code, invite.CreatedBy, invite.Status,
		invite.ExpiresAt, invite.AcceptedAt, invite.CreatedAt)
	return err
}

func (r *InviteRepository) GetByID(ctx context.Context, id string) (*domain.Invite, error) {
	invite := &domain.Invite{}
	var acceptedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, inviteByIDQuery, id).Scan(
		&invite.ID, &invite.Email, &invite.Code, &invite.CreatedBy, &invite.Status,
		&invite.ExpiresAt, &acceptedAt, &invite.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if acceptedAt.Valid {
		invite.AcceptedAt = &acceptedAt.Time
	}
	return invite, nil
}

func (r *InviteRepository) GetByCode(ctx context.Context, code string) (*domain.Invite, error) {
	invite := &domain.Invite{}
	var acceptedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, inviteByCodeQuery, code).Scan(
		&invite.ID, &invite.Email, &invite.Code, &invite.CreatedBy, &invite.Status,
		&invite.ExpiresAt, &acceptedAt, &invite.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if acceptedAt.Valid {
		invite.AcceptedAt = &acceptedAt.Time
	}
	return invite, nil
}

func (r *InviteRepository) GetByEmail(ctx context.Context, email string) (*domain.Invite, error) {
	invite := &domain.Invite{}
	var acceptedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, inviteByEmailQuery, email).Scan(
		&invite.ID, &invite.Email, &invite.Code, &invite.CreatedBy, &invite.Status,
		&invite.ExpiresAt, &acceptedAt, &invite.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if acceptedAt.Valid {
		invite.AcceptedAt = &acceptedAt.Time
	}
	return invite, nil
}

// buildInviteWhere returns the " WHERE ..." clause and args shared by List
// and Count. argN is where positional placeholders start (0 = none used yet).
// buildInviteWhere builds the shared WHERE for List and Count.
//
// "expired" is derived, not stored: the terminal status is only written when
// someone opens the invite link (see InviteService.GetInviteByToken), so an
// invite that quietly passed expires_at still sits in the table as 'pending'.
// Filtering therefore treats pending-and-past-due as expired, and pending as
// pending-and-still-valid — otherwise the counts and the status column
// disagree with each other.
func (r *InviteRepository) buildInviteWhere(filter port.InviteFilter, now time.Time) (string, []any) {
	var where []string
	var args []any
	argIdx := 1

	if filter.Search != nil && *filter.Search != "" {
		// Postgres does a substring match, served by the pg_trgm GIN index on
		// invites(email). MySQL and SQLite have no portable substring index,
		// so they fall back to a prefix match that the plain btree can serve —
		// the same trade-off UserRepository.buildWhere makes.
		searchTerm := "%" + *filter.Search + "%"
		op := "ILIKE"
		if r.db.Driver() == "mysql" || r.db.Driver() == "sqlite" || r.db.Driver() == "sqlite3" {
			op = "LIKE"
			searchTerm = *filter.Search + "%"
		}
		where = append(where, fmt.Sprintf("email %s $%d", op, argIdx))
		args = append(args, searchTerm)
		argIdx++
	}

	if filter.Status != nil && *filter.Status != "" {
		switch domain.InviteStatus(*filter.Status) {
		case domain.InviteExpired:
			// Either already written as expired, or pending and past due.
			where = append(where, fmt.Sprintf(
				"(status = 'expired' OR (status = 'pending' AND expires_at <= $%d))", argIdx))
			args = append(args, now)
		case domain.InvitePending:
			where = append(where, fmt.Sprintf("(status = 'pending' AND expires_at > $%d)", argIdx))
			args = append(args, now)
		default:
			where = append(where, fmt.Sprintf("status = $%d", argIdx))
			args = append(args, *filter.Status)
		}
		argIdx++
	}

	if len(where) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(where, " AND "), args
}

// deriveInviteStatus reports a pending-but-past-due invite as expired.
//
// Applied on the admin list read only, deliberately: GetByCode/GetByID feed
// the accept flow, which distinguishes "revoked" from "expired" itself and
// writes the terminal status. Deriving there would turn ErrInviteExpired into
// ErrInviteNotFound.
func deriveInviteStatus(inv *domain.Invite, now time.Time) {
	if inv.Status == domain.InvitePending && now.After(inv.ExpiresAt) {
		inv.Status = domain.InviteExpired
	}
}

// Count returns how many invites match filter (Offset/Limit ignored).
func (r *InviteRepository) Count(ctx context.Context, filter port.InviteFilter) (int, error) {
	where, args := r.buildInviteWhere(filter, time.Now().UTC())
	var total int
	q := r.db.Rebind("SELECT COUNT(*) FROM invites" + where)
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (r *InviteRepository) List(ctx context.Context, filter port.InviteFilter) ([]domain.Invite, error) {
	now := time.Now().UTC()
	where, args := r.buildInviteWhere(filter, now)
	argIdx := len(args) + 1

	orderCol := inviteOrderByWhitelist[filter.OrderBy]
	if orderCol == "" {
		orderCol = "created_at"
	}
	orderDir := "DESC"
	if strings.EqualFold(filter.OrderDirection, "asc") {
		orderDir = "ASC"
	}

	query := fmt.Sprintf(`SELECT `+inviteSelectColumns+`
		FROM invites%s ORDER BY %s %s`, where, orderCol, orderDir)
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, filter.Limit)
		argIdx++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, r.db.Rebind(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invites := []domain.Invite{}
	for rows.Next() {
		var inv domain.Invite
		var acceptedAt sql.NullTime
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.Code, &inv.CreatedBy, &inv.Status,
			&inv.ExpiresAt, &acceptedAt, &inv.CreatedAt); err != nil {
			return nil, err
		}
		if acceptedAt.Valid {
			inv.AcceptedAt = &acceptedAt.Time
		}
		deriveInviteStatus(&inv, now)
		invites = append(invites, inv)
	}
	return invites, rows.Err()
}

func (r *InviteRepository) Update(ctx context.Context, invite *domain.Invite) error {
	_, err := r.db.ExecContext(ctx, inviteUpdateQuery,
		invite.Email, invite.Code, invite.CreatedBy, invite.Status,
		invite.ExpiresAt, invite.AcceptedAt, invite.ID)
	return err
}

func (r *InviteRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, inviteDeleteQuery, id)
	return err
}

func (r *InviteRepository) ClaimInvite(ctx context.Context, code string, acceptedAt time.Time) (bool, error) {
	result, err := r.db.ExecContext(ctx, inviteClaimQuery, acceptedAt, code)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
