package sqlstore

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type InviteRepository struct {
	db *DB
}

func NewInviteRepository(db *DB) *InviteRepository {
	return &InviteRepository{db: db}
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

func (r *InviteRepository) List(ctx context.Context, filter port.InviteFilter) ([]domain.Invite, int, error) {
	where := ""
	args := []any{}
	argN := 0

	if filter.Search != nil && *filter.Search != "" {
		argN++
		args = append(args, "%"+*filter.Search+"%")
		where = fmt.Sprintf(" WHERE LOWER(email) LIKE LOWER($%d)", argN)
	}
	if filter.Status != nil && *filter.Status != "" {
		if where == "" {
			where = " WHERE"
		} else {
			where += " AND"
		}
		argN++
		args = append(args, *filter.Status)
		where += fmt.Sprintf(" status = $%d", argN)
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM invites" + where
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	argN++
	args = append(args, filter.Limit)
	argN++
	args = append(args, filter.Offset)

	query := fmt.Sprintf(`SELECT `+inviteSelectColumns+`
		FROM invites%s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, where, argN-1, argN)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var invites []domain.Invite
	for rows.Next() {
		var inv domain.Invite
		var acceptedAt sql.NullTime
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.Code, &inv.CreatedBy, &inv.Status,
			&inv.ExpiresAt, &acceptedAt, &inv.CreatedAt); err != nil {
			return nil, 0, err
		}
		if acceptedAt.Valid {
			inv.AcceptedAt = &acceptedAt.Time
		}
		invites = append(invites, inv)
	}
	if invites == nil {
		invites = []domain.Invite{}
	}
	return invites, total, rows.Err()
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
