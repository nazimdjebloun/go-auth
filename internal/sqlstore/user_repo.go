package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// UserRepository stores user accounts.
type UserRepository struct {
	db             *DB
	appPermissions bool
}

// WithAppPermissions selects the protected app identity for last-admin guards
// and omits the fixed account role from account writes and returned users.
// Configure once during wiring, before serving requests.
func (r *UserRepository) WithAppPermissions() *UserRepository { r.appPermissions = true; return r }

// NewUserRepository returns a user repository.
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

// userNullables holds the nullable timestamp columns during a scan. They need
// sql.NullTime on the way in and become pointers on domain.User afterward.
type userNullables struct {
	verifiedAt  sql.NullTime
	bannedAt    sql.NullTime
	lastLoginAt sql.NullTime
}

// userScanDest lists the scan targets for userSelectColumns, in that exact
// order. It exists so scanRow and the session+user join in SessionRepository
// share one list: a column added to userSelectColumns but not here is a scan
// error in both, rather than a silent mismatch in whichever one was forgotten.
func userScanDest(u *domain.User, n *userNullables) []any {
	return []any{
		&u.ID, &u.Email, &u.PasswordHash, &u.PasswordPepperVersion, &u.Name, &u.Role,
		&u.IsVerified, &n.verifiedAt, &u.IsBanned, &n.bannedAt, &u.TwoFactorEnabled,
		&u.OrgOwnerCount, &n.lastLoginAt, &u.CreatedAt, &u.UpdatedAt,
		&u.AppRoleID, &u.AppRoleAssignmentRevision,
	}
}

// finishUser moves the scanned nullables onto the user. Call after any scan
// that used userScanDest.
func finishUser(u *domain.User, n *userNullables) {
	if n.verifiedAt.Valid {
		u.VerifiedAt = &n.verifiedAt.Time
	}
	if n.bannedAt.Valid {
		u.BannedAt = &n.bannedAt.Time
	}
	if n.lastLoginAt.Valid {
		u.LastLoginAt = &n.lastLoginAt.Time
	}
}

func (r *UserRepository) scanRow(s scanner) (*domain.User, error) {
	u := &domain.User{}
	var n userNullables
	if err := s.Scan(userScanDest(u, &n)...); err != nil {
		return nil, err
	}
	finishUser(u, &n)
	if r.appPermissions {
		u.Role = ""
	}
	return u, nil
}

// Create stores a user.
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	if r.appPermissions {
		_, err := r.db.ExecContext(ctx, userCreateAppQuery,
			user.ID, user.Email, user.PasswordHash, user.PasswordPepperVersion, user.Name,
			user.IsVerified, user.VerifiedAt, user.IsBanned, user.TwoFactorEnabled,
			user.OrgOwnerCount, user.CreatedAt, user.UpdatedAt, user.AppRoleID, user.AppRoleAssignmentRevision)
		if err == nil {
			user.Role = ""
		}
		return wrapCreateErr(r.db.Driver(), err)
	}
	_, err := r.db.ExecContext(ctx, userCreateQuery,
		user.ID, user.Email, user.PasswordHash, user.PasswordPepperVersion, user.Name, user.Role,
		user.IsVerified, user.VerifiedAt, user.IsBanned, user.TwoFactorEnabled,
		user.OrgOwnerCount, user.CreatedAt, user.UpdatedAt, user.AppRoleID, user.AppRoleAssignmentRevision)
	return wrapCreateErr(r.db.Driver(), err)
}

// GetByID returns a user by ID or nil when absent.
func (r *UserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	user, err := r.scanRow(r.db.QueryRowContext(ctx, userByIDQuery, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetByEmail returns a user by email or nil when absent.
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	user, err := r.scanRow(r.db.QueryRowContext(ctx, userByEmailQuery, email))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return user, nil
}

// Update changes a user's profile and verification fields.
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	_, err := r.db.ExecContext(ctx, userUpdateQuery,
		user.Email, user.Name, user.IsVerified, user.VerifiedAt,
		user.UpdatedAt, user.ID)
	return err
}

// SetBanStatus changes a user's ban status.
func (r *UserRepository) SetBanStatus(ctx context.Context, userID string, isBanned bool, bannedAt *time.Time, updatedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, userBanQuery,
		isBanned, bannedAt, updatedAt, userID)
	return err
}

// SetTwoFactorEnabled changes a user's two-factor status.
func (r *UserRepository) SetTwoFactorEnabled(ctx context.Context, userID string, enabled bool, updatedAt time.Time) error {
	_, err := r.db.ExecContext(ctx, userSetTwoFactorQuery, enabled, updatedAt, userID)
	return err
}

// SetPasswordAndVerify consumes a token, sets the password, and verifies the user.
func (r *UserRepository) SetPasswordAndVerify(ctx context.Context, userID string, passwordHash string, pepperVersion *uint32, tokenID string) (bool, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()

	// Claim the one-time code BEFORE writing the password, gating on it
	// still being unused: only the request that flips used_at proceeds, so
	// concurrent confirms with the same code cannot both land — the loser
	// rolls back without touching the winner's password.
	claimed, err := affected(tx.ExecContext(ctx, r.db.Rebind(tokenMarkUsedIfUnusedQuery), now, tokenID))
	if err != nil {
		return false, err
	}
	if !claimed {
		return false, nil
	}

	updated, err := affected(tx.ExecContext(ctx, r.db.Rebind(userSetPasswordQuery), passwordHash, pepperVersion, now, now, userID))
	if err != nil {
		return false, err
	}
	if !updated {
		// A different code or credential writer won the race. Rolling back
		// also restores this code so the transaction has no partial effect.
		return false, nil
	}

	return true, tx.Commit()
}

// UpdatePasswordHash replaces a matching password hash and pepper version.
func (r *UserRepository) UpdatePasswordHash(ctx context.Context, userID, oldHash string, oldPepperVersion *uint32, newHash string, newPepperVersion *uint32, updatedAt time.Time) (bool, error) {
	oldPepperVersionValue := int64(0)
	if oldPepperVersion != nil {
		oldPepperVersionValue = int64(*oldPepperVersion)
	}
	newPepperVersionValue := int64(0)
	if newPepperVersion != nil {
		newPepperVersionValue = int64(*newPepperVersion)
	}
	result, err := r.db.ExecContext(
		ctx,
		userUpdatePasswordHashQuery,
		newHash,
		newPepperVersion,
		updatedAt,
		userID,
		oldHash,
		oldPepperVersionValue,
		newPepperVersionValue,
	)
	if err != nil {
		return false, fmt.Errorf("updating password hash: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("reading password hash update result: %w", err)
	}
	return rows == 1, nil
}

// ListPasswordPepperVersions returns the distinct stored pepper versions.
func (r *UserRepository) ListPasswordPepperVersions(ctx context.Context) ([]uint32, error) {
	rows, err := r.db.QueryContext(ctx, userPasswordPepperVersionsQuery)
	if err != nil {
		return nil, fmt.Errorf("listing password pepper versions: %w", err)
	}

	var versions []uint32
	for rows.Next() {
		var version uint32
		if err := rows.Scan(&version); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scanning password pepper version: %w", err)
		}
		if version == 0 {
			_ = rows.Close()
			return nil, fmt.Errorf("scanning password pepper version: zero is reserved for unpeppered passwords")
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterating password pepper versions: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("closing password pepper versions: %w", err)
	}
	return versions, nil
}

// Delete removes a user by ID.
func (r *UserRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, userDeleteQuery, id)
	return err
}

// UpdateLastLoginAt records a user's last login time.
func (r *UserRepository) UpdateLastLoginAt(ctx context.Context, userID string, t time.Time) error {
	_, err := r.db.ExecContext(ctx, userUpdateLastLoginQuery, t, t, userID)
	return err
}

// buildWhere is shared by List and CountByDay — both need the exact same
// filter->SQL translation, only what they do with the resulting rows differs.
func (r *UserRepository) buildWhere(filter port.UserFilter) (string, []any) {
	where := []string{"1=1"}
	args := []any{}
	argIdx := 1

	if len(filter.IDs) > 0 {
		placeholders := make([]string, len(filter.IDs))
		for i, id := range filter.IDs {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, id)
			argIdx++
		}
		where = append(where, fmt.Sprintf("id IN (%s)", strings.Join(placeholders, ", ")))
	}
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
	if filter.AppRoleID != nil {
		where = append(where, fmt.Sprintf("app_role_id = $%d", argIdx))
		args = append(args, *filter.AppRoleID)
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
	if filter.TwoFactorEnabled != nil {
		where = append(where, fmt.Sprintf("two_factor_enabled = $%d", argIdx))
		args = append(args, *filter.TwoFactorEnabled)
		argIdx++
	}
	if filter.NeverLoggedIn != nil && *filter.NeverLoggedIn {
		where = append(where, "last_login_at IS NULL")
	}
	if filter.LastLoginBefore != nil {
		where = append(where, fmt.Sprintf("last_login_at < $%d", argIdx))
		args = append(args, *filter.LastLoginBefore)
		argIdx++
	}
	if filter.CreatedAfter != nil {
		where = append(where, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, *filter.CreatedAfter)
		argIdx++
	}
	if filter.CreatedBefore != nil {
		where = append(where, fmt.Sprintf("created_at <= $%d", argIdx))
		args = append(args, *filter.CreatedBefore)
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		// Postgres does a substring match, served by the pg_trgm GIN indexes
		// on users(name) / users(email). MySQL and SQLite have no portable
		// substring index, so they fall back to a prefix match ("term%")
		// that a plain btree can serve — matching the start of a name or
		// email is the common admin lookup anyway.
		searchTerm := "%" + *filter.Search + "%"
		op := "ILIKE"
		if r.db.UsesPositionalParams() {
			op = "LIKE"
			searchTerm = *filter.Search + "%"
		}
		// Two distinct placeholders, not one reused twice: DB.Rebind rewrites
		// every textual "$N" occurrence to "?" positionally for mysql/sqlite,
		// so a placeholder used twice in the query text must still be backed
		// by two separate (equal-valued) entries in args, one per occurrence.
		where = append(where, fmt.Sprintf("(name %s $%d OR email %s $%d)", op, argIdx, op, argIdx+1))
		args = append(args, searchTerm, searchTerm)
	}

	return strings.Join(where, " AND "), args
}

// List returns users matching the filter.
func (r *UserRepository) List(ctx context.Context, filter port.UserFilter) ([]domain.User, error) {
	whereClause, args := r.buildWhere(filter)
	argIdx := len(args) + 1

	orderCol := orderByWhitelist[string(filter.OrderBy)]
	if orderCol == "" {
		orderCol = "created_at"
	}
	orderDir := "DESC"
	if filter.OrderDirection == api.SortAscending {
		orderDir = "ASC"
	}

	query := fmt.Sprintf(`
		SELECT %s FROM users WHERE %s ORDER BY %s %s`,
		userSelectColumns, whereClause, orderCol, orderDir)
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
		args = append(args, filter.Limit, filter.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	users := []domain.User{}
	for rows.Next() {
		u, err := r.scanRow(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		users = append(users, *u)
	}

	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("user list close: %w", err)
	}
	return users, nil
}

// Count returns how many users match filter. Pagination/order on filter are
// irrelevant here; only the WHERE predicates matter.
func (r *UserRepository) Count(ctx context.Context, filter port.UserFilter) (int, error) {
	whereClause, args := r.buildWhere(filter)
	var total int
	q := fmt.Sprintf("SELECT COUNT(*) FROM users WHERE %s", whereClause)
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// CountByDay returns registrations per day matching filter — Offset/Limit on
// filter are ignored, the result is naturally bounded by whatever date range
// filter.CreatedAfter/CreatedBefore narrows it to.
func (r *UserRepository) CountByDay(ctx context.Context, filter port.UserFilter) ([]api.DailyCount, error) {
	whereClause, args := r.buildWhere(filter)

	var dayExpr string
	switch r.db.Driver() {
	case "mysql":
		dayExpr = "DATE(created_at)"
	case "sqlite", "sqlite3":
		// Not date(created_at): modernc.org/sqlite stores time.Time as
		// RFC3339Nano text ("...2026-08-19T19:21:36.275883607Z"), and
		// SQLite's date() can't parse 9-digit fractional seconds — it
		// silently returns NULL. The stored format's first 10 characters
		// are always the ISO date, so substr sidesteps date() entirely.
		dayExpr = "substr(created_at, 1, 10)"
	default: // postgres
		dayExpr = "date_trunc('day', created_at)"
	}

	query := fmt.Sprintf(`SELECT %s AS day, COUNT(*) FROM users WHERE %s GROUP BY day ORDER BY day`, dayExpr, whereClause)
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	var counts []api.DailyCount
	for rows.Next() {
		var c api.DailyCount
		var day time.Time
		if r.db.Driver() == "sqlite" || r.db.Driver() == "sqlite3" {
			// modernc.org/sqlite returns date() as a string, not a time.Time.
			var dayStr string
			if err := rows.Scan(&dayStr, &c.Count); err != nil {
				_ = rows.Close()
				return nil, err
			}
			day, err = time.Parse("2006-01-02", dayStr)
			if err != nil {
				_ = rows.Close()
				return nil, err
			}
		} else {
			if err := rows.Scan(&day, &c.Count); err != nil {
				_ = rows.Close()
				return nil, err
			}
		}
		c.Date = day
		counts = append(counts, c)
	}
	if counts == nil {
		counts = []api.DailyCount{}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("user daily counts close: %w", err)
	}
	return counts, nil
}
