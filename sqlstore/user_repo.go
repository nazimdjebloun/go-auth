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

type UserRepository struct {
	db *DB
}

func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

var orderByWhitelist = map[string]string{
	"created_at": "created_at",
	"updated_at": "updated_at",
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRow(s scanner) (*domain.User, error) {
	u := &domain.User{}
	var bannedAt sql.NullTime
	var verifiedAt sql.NullTime
	if err := s.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Role,
		&u.IsVerified, &verifiedAt, &u.IsBanned, &bannedAt, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if verifiedAt.Valid {
		u.VerifiedAt = &verifiedAt.Time
	}
	if bannedAt.Valid {
		u.BannedAt = &bannedAt.Time
	}
	return u, nil
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	_, err := r.db.ExecContext(ctx, userCreateQuery,
		user.ID, user.Email, user.PasswordHash, user.Name, user.Role,
		user.IsVerified, user.VerifiedAt, user.IsBanned, user.CreatedAt, user.UpdatedAt)
	return err
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	user, err := scanRow(r.db.QueryRowContext(ctx, userByIDQuery, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	user, err := scanRow(r.db.QueryRowContext(ctx, userByEmailQuery, email))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	_, err := r.db.ExecContext(ctx, userUpdateQuery,
		user.Email, user.PasswordHash, user.Name, user.Role,
		user.IsVerified, user.VerifiedAt, user.IsBanned, user.UpdatedAt, user.ID)
	return err
}

func (r *UserRepository) SetBanStatus(ctx context.Context, userID string, isBanned bool, bannedAt *time.Time, updatedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, userBanQuery,
		isBanned, bannedAt, updatedAt, userID)
	return err
}

func (r *UserRepository) SetPasswordAndVerify(ctx context.Context, userID string, passwordHash string, tokenID string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC()

	_, err = tx.ExecContext(ctx, r.db.Rebind(userSetPasswordQuery), passwordHash, now, now, userID)
	if err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx, r.db.Rebind(`
		UPDATE verification_tokens SET used_at=$1 WHERE id=$2 AND used_at IS NULL`), now, tokenID)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, userDeleteQuery, id)
	return err
}

func (r *UserRepository) List(ctx context.Context, filter port.UserFilter) ([]domain.User, int, error) {
	where := []string{"1=1"}
	args := []any{}
	argIdx := 1

	if filter.Email != nil {
		where = append(where, fmt.Sprintf("email LIKE $%d", argIdx))
		args = append(args, "%"+*filter.Email+"%")
		argIdx++
	}
	if filter.Role != nil {
		where = append(where, fmt.Sprintf("role = $%d", argIdx))
		args = append(args, *filter.Role)
		argIdx++
	}
	if filter.IsBanned != nil {
		where = append(where, fmt.Sprintf("is_banned = $%d", argIdx))
		args = append(args, *filter.IsBanned)
		argIdx++
	}
	if filter.IsVerified != nil {
		where = append(where, fmt.Sprintf("is_verified = $%d", argIdx))
		args = append(args, *filter.IsVerified)
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		searchTerm := "%" + *filter.Search + "%"
		where = append(where, fmt.Sprintf("(name ILIKE $%d OR email ILIKE $%d)", argIdx, argIdx))
		args = append(args, searchTerm)
		argIdx++
	}

	whereClause := strings.Join(where, " AND ")

	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE %s", whereClause)
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderCol := orderByWhitelist[filter.OrderBy]
	if orderCol == "" {
		orderCol = "created_at"
	}
	orderDir := "DESC"
	if strings.EqualFold(filter.OrderDirection, "asc") {
		orderDir = "ASC"
	}

	if filter.Limit <= 0 {
		query := fmt.Sprintf(`
			SELECT %s FROM users WHERE %s ORDER BY %s %s`, userSelectColumns, whereClause, orderCol, orderDir)

		rows, err := r.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()

		var users []domain.User
		for rows.Next() {
			u, err := scanRow(rows)
			if err != nil {
				return nil, 0, err
			}
			users = append(users, *u)
		}
		if users == nil {
			users = []domain.User{}
		}
		return users, total, rows.Err()
	}

	limit := filter.Limit
	offset := filter.Offset

	query := fmt.Sprintf(`
		SELECT %s FROM users WHERE %s ORDER BY %s %s LIMIT $%d OFFSET $%d`,
		userSelectColumns, whereClause, orderCol, orderDir, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		u, err := scanRow(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, *u)
	}
	if users == nil {
		users = []domain.User{}
	}

	return users, total, rows.Err()
}
