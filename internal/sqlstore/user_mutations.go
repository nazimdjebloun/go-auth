package sqlstore

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

var _ port.UserRepository = (*UserRepository)(nil)

// UpdateName changes a user's name.
func (r *UserRepository) UpdateName(ctx context.Context, userID, name string, updatedAt time.Time) (bool, error) {
	return affected(r.db.ExecContext(ctx, `UPDATE users SET name=$1, updated_at=$2 WHERE id=$3`, name, updatedAt, userID))
}

// VerifyEmailIfMatches verifies a user when the stored email matches.
func (r *UserRepository) VerifyEmailIfMatches(ctx context.Context, userID, expectedEmail string, verifiedAt time.Time) (bool, error) {
	query := `UPDATE users SET is_verified=true, verified_at=$1, updated_at=$2 WHERE id=$3 AND email=$4`
	// MySQL's default email collation is case-insensitive; verification must
	// bind to the exact address observed, just as on PostgreSQL and SQLite.
	if r.db.Driver() == "mysql" {
		query = `UPDATE users SET is_verified=true, verified_at=$1, updated_at=$2 WHERE id=$3 AND BINARY email=BINARY $4`
	}
	return affected(r.db.ExecContext(ctx, query, verifiedAt, verifiedAt, userID, expectedEmail))
}
