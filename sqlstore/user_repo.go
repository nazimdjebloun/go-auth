package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type UserRepository struct {
	db *DB
}

func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO users (id, email, password_hash, name, role, is_verified, verified_at, is_banned, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		user.ID, user.Email, user.PasswordHash, user.Name, user.Role,
		user.IsVerified, user.VerifiedAt, user.IsBanned, user.CreatedAt, user.UpdatedAt)
	return err
}

func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	user := &domain.User{}
	var bannedAt sql.NullTime
	var verifiedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, name, role, is_verified, verified_at, is_banned, banned_at, created_at, updated_at
		FROM users WHERE id = $1`, id).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Role,
		&user.IsVerified, &verifiedAt, &user.IsBanned, &bannedAt, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if verifiedAt.Valid {
		user.VerifiedAt = &verifiedAt.Time
	}
	if bannedAt.Valid {
		user.BannedAt = &bannedAt.Time
	}
	return user, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	user := &domain.User{}
	var bannedAt sql.NullTime
	var verifiedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT id, email, password_hash, name, role, is_verified, verified_at, is_banned, banned_at, created_at, updated_at
		FROM users WHERE email = $1`, email).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Role,
		&user.IsVerified, &verifiedAt, &user.IsBanned, &bannedAt, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if verifiedAt.Valid {
		user.VerifiedAt = &verifiedAt.Time
	}
	if bannedAt.Valid {
		user.BannedAt = &bannedAt.Time
	}
	return user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	_, err := r.db.ExecContext(ctx, `
		UPDATE users SET email=$1, password_hash=$2, name=$3, role=$4,
			is_verified=$5, verified_at=$6, is_banned=$7, banned_at=$8, updated_at=$9
		WHERE id=$10`,
		user.Email, user.PasswordHash, user.Name, user.Role,
		user.IsVerified, user.VerifiedAt, user.IsBanned, user.BannedAt, user.UpdatedAt, user.ID)
	return err
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
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

	// Build ORDER BY
	orderCol := "created_at"
	if filter.OrderBy == "updated_at" {
		orderCol = "updated_at"
	}
	orderDir := "DESC"
	if filter.OrderDirection == "asc" {
		orderDir = "ASC"
	}

	colList := "id, email, password_hash, name, role, is_verified, verified_at, is_banned, banned_at, created_at, updated_at"

	// When Limit is 0, return all matching users (no pagination)
	if filter.Limit <= 0 {
		query := fmt.Sprintf(`
			SELECT %s FROM users WHERE %s ORDER BY %s %s`, colList, whereClause, orderCol, orderDir)

		rows, err := r.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, 0, err
		}
		defer rows.Close()

		var users []domain.User
		for rows.Next() {
			var u domain.User
			var bannedAt sql.NullTime
			var verifiedAt sql.NullTime
			if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Role,
				&u.IsVerified, &verifiedAt, &u.IsBanned, &bannedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
				return nil, 0, err
			}
			if verifiedAt.Valid {
				u.VerifiedAt = &verifiedAt.Time
			}
			if bannedAt.Valid {
				u.BannedAt = &bannedAt.Time
			}
			users = append(users, u)
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
		colList, whereClause, orderCol, orderDir, argIdx, argIdx+1)
	args = append(args, limit, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var u domain.User
		var bannedAt sql.NullTime
		var verifiedAt sql.NullTime
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Role,
			&u.IsVerified, &verifiedAt, &u.IsBanned, &bannedAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, 0, err
		}
		if verifiedAt.Valid {
			u.VerifiedAt = &verifiedAt.Time
		}
		if bannedAt.Valid {
			u.BannedAt = &bannedAt.Time
		}
		users = append(users, u)
	}
	if users == nil {
		users = []domain.User{}
	}

	return users, total, rows.Err()
}
