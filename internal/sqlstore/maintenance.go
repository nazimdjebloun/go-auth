package sqlstore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

var (
	_ port.ExpiredRowDeleter = (*SessionRepository)(nil)
	_ port.ExpiredRowDeleter = (*TokenRepository)(nil)
)

// deleteExpiredBatch selects at most limit expired primary keys, then deletes
// exactly those rows.
//
// Two statements rather than one DELETE ... LIMIT because neither single
// statement is portable: LIMIT on DELETE is MySQL-only, and LIMIT inside an
// IN-subquery is rejected by MySQL. SELECT ... LIMIT is supported by all
// three drivers, and placeholders are rewritten by DB.Rebind, so this one
// implementation stays correct on PostgreSQL, MySQL, and SQLite.
//
// selectArgs are the arguments for selectQuery, limit included — callers pass
// them explicitly because DB.Rebind rewrites $N positionally, so a query may
// not reuse a placeholder number.
func deleteExpiredBatch(ctx context.Context, db *DB, selectQuery string, selectArgs []any, deletePrefix string) (int, error) {
	rows, err := db.QueryContext(ctx, selectQuery, selectArgs...)
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(ids) == 0 {
		return 0, nil
	}

	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}
	query := deletePrefix + " (" + strings.Join(placeholders, ", ") + ")"

	res, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// DeleteExpiredBatch removes sessions that are dead on both clocks: the
// session itself expired AND its refresh token expired (or was never issued).
// A session whose refresh token expired while the session was still live is
// left alone — deleting it would end an active login early, which is not
// this maintenance's job.
func (r *SessionRepository) DeleteExpiredBatch(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("sqlstore: maintenance batch limit must be positive")
	}
	// cutoff twice: see sessionExpiredIDQuery's note on placeholder reuse.
	return deleteExpiredBatch(ctx, r.db, sessionExpiredIDQuery, []any{cutoff, cutoff, limit}, "DELETE FROM sessions WHERE id IN")
}

// DeleteExpiredBatch removes verification, reset, set-password, and
// delete-account tokens whose expiry has passed the cutoff.
func (r *TokenRepository) DeleteExpiredBatch(ctx context.Context, cutoff time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, fmt.Errorf("sqlstore: maintenance batch limit must be positive")
	}
	return deleteExpiredBatch(ctx, r.db, tokenExpiredIDQuery, []any{cutoff, limit}, "DELETE FROM verification_tokens WHERE id IN")
}
