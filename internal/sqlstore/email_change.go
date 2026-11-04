package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

// EmailChangeRepository persists confirmation state under the user lock.
type EmailChangeRepository struct{ db *DB }

// NewEmailChangeRepository uses the pre-applied email_change_requests table.
func NewEmailChangeRepository(db *DB) *EmailChangeRepository { return &EmailChangeRepository{db: db} }

var _ port.EmailChangeStore = (*EmailChangeRepository)(nil)

const emailChangeColumns = `user_id, id, session_id, scope, current_email, new_email,
	current_code_hash, new_code_hash, identity_hash, status, created_at, expires_at,
	budget_started_at, current_sent_at, new_sent_at, starts, attempts, current_resends, new_resends`

// Load locks a lineage after its owning user has been locked.
func (r *EmailChangeRepository) Load(ctx context.Context, userID string) (*port.EmailChangeRequest, error) {
	if _, ok := txFromContext(ctx); !ok {
		return nil, errors.New("email change load requires a transaction")
	}
	query := `SELECT ` + emailChangeColumns + ` FROM email_change_requests WHERE user_id=$1`
	if r.db.Driver() != "sqlite" && r.db.Driver() != "sqlite3" {
		query += " FOR UPDATE"
	}
	var v port.EmailChangeRequest
	var created, expires, budget, currentSent, newSent int64
	err := r.db.QueryRowContext(ctx, query, userID).Scan(&v.UserID, &v.ID, &v.SessionID, &v.Scope,
		&v.CurrentEmail, &v.NewEmail, &v.CurrentCodeHash, &v.NewCodeHash, &v.IdentityHash, &v.Status,
		&created, &expires, &budget, &currentSent, &newSent, &v.Starts, &v.Attempts, &v.CurrentResends, &v.NewResends)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v.CreatedAt, v.ExpiresAt, v.BudgetStartedAt = time.UnixMicro(created).UTC(), time.UnixMicro(expires).UTC(), time.UnixMicro(budget).UTC()
	v.CurrentSentAt, v.NewSentAt = time.UnixMicro(currentSent).UTC(), time.UnixMicro(newSent).UTC()
	return &v, nil
}

// Save replaces the account slot without resetting its caller-managed budget.
func (r *EmailChangeRepository) Save(ctx context.Context, v *port.EmailChangeRequest) error {
	if _, ok := txFromContext(ctx); !ok {
		return errors.New("email change save requires a transaction")
	}
	query := `INSERT INTO email_change_requests (` + emailChangeColumns + `)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`
	if r.db.Driver() == "mysql" {
		query += ` ON DUPLICATE KEY UPDATE id=VALUES(id), session_id=VALUES(session_id), scope=VALUES(scope),
		current_email=VALUES(current_email), new_email=VALUES(new_email), current_code_hash=VALUES(current_code_hash),
		new_code_hash=VALUES(new_code_hash), identity_hash=VALUES(identity_hash), status=VALUES(status),
		created_at=VALUES(created_at), expires_at=VALUES(expires_at), budget_started_at=VALUES(budget_started_at),
		current_sent_at=VALUES(current_sent_at), new_sent_at=VALUES(new_sent_at), starts=VALUES(starts),
		attempts=VALUES(attempts), current_resends=VALUES(current_resends), new_resends=VALUES(new_resends)`
	} else {
		query += ` ON CONFLICT (user_id) DO UPDATE SET id=excluded.id, session_id=excluded.session_id, scope=excluded.scope,
		current_email=excluded.current_email, new_email=excluded.new_email, current_code_hash=excluded.current_code_hash,
		new_code_hash=excluded.new_code_hash, identity_hash=excluded.identity_hash, status=excluded.status,
		created_at=excluded.created_at, expires_at=excluded.expires_at, budget_started_at=excluded.budget_started_at,
		current_sent_at=excluded.current_sent_at, new_sent_at=excluded.new_sent_at, starts=excluded.starts,
		attempts=excluded.attempts, current_resends=excluded.current_resends, new_resends=excluded.new_resends`
	}
	_, err := r.db.ExecContext(ctx, query, v.UserID, v.ID, v.SessionID, v.Scope, v.CurrentEmail, v.NewEmail,
		v.CurrentCodeHash, v.NewCodeHash, v.IdentityHash, v.Status, v.CreatedAt.UnixMicro(), v.ExpiresAt.UnixMicro(),
		v.BudgetStartedAt.UnixMicro(), v.CurrentSentAt.UnixMicro(), v.NewSentAt.UnixMicro(), v.Starts, v.Attempts, v.CurrentResends, v.NewResends)
	return err
}

// ChangeAddress guards the exact previous address and preserves other metadata.
func (r *EmailChangeRepository) ChangeAddress(ctx context.Context, userID, oldEmail, newEmail string, now time.Time) (bool, error) {
	query := `UPDATE users SET email=$1, is_verified=true, verified_at=$2, updated_at=$3 WHERE id=$4 AND email=$5`
	if r.db.Driver() == "mysql" {
		query = `UPDATE users SET email=$1, is_verified=true, verified_at=$2, updated_at=$3 WHERE id=$4 AND BINARY email=BINARY $5`
	}
	result, err := r.db.ExecContext(ctx, query, newEmail, now, now, userID, oldEmail)
	if err != nil {
		return false, wrapCreateErr(r.db.Driver(), err)
	}
	return affected(result, nil)
}

// InvalidateCredentials also removes pending account-bound OAuth link states.
// Public OAuth login states have no user ID and continue through current policy.
func (r *EmailChangeRepository) InvalidateCredentials(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM verification_tokens WHERE user_id=$1`, userID)
	return err
}

// DiscardVersion cannot cancel a replacement request or a newer resend.
func (r *EmailChangeRepository) DiscardVersion(ctx context.Context, v *port.EmailChangeRequest) error {
	_, err := r.db.ExecContext(ctx, `UPDATE email_change_requests SET status='cancelled', current_code_hash='', new_code_hash=''
		WHERE user_id=$1 AND id=$2 AND current_code_hash=$3 AND new_code_hash=$4 AND status='pending'`,
		v.UserID, v.ID, v.CurrentCodeHash, v.NewCodeHash)
	return err
}

// CancelForUser preserves the account's start budget while destroying its proofs.
func (r *EmailChangeRepository) CancelForUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE email_change_requests SET status='cancelled', current_code_hash='', new_code_hash=''
		WHERE user_id=$1 AND status='pending'`, userID)
	return err
}

// PruneExpired clears a bounded batch without deleting account start budgets.
func (r *EmailChangeRepository) PruneExpired(ctx context.Context, now time.Time) error {
	// Select without write locks, then update by primary key. A full-table
	// UPDATE could lock unrelated live requests on MySQL's default isolation.
	rows, err := r.db.QueryContext(ctx, `SELECT user_id, id FROM email_change_requests
		WHERE status='pending' AND expires_at <= $1
		AND (current_code_hash<>'' OR new_code_hash<>'') LIMIT 100`, now.UnixMicro())
	if err != nil {
		return err
	}
	defer rows.Close()
	type version struct{ userID, requestID string }
	var versions []version
	for rows.Next() {
		var v version
		if err := rows.Scan(&v.userID, &v.requestID); err != nil {
			return err
		}
		versions = append(versions, v)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, v := range versions {
		// A concurrent replacement has a new ID and must retain its proofs.
		if _, err := r.db.ExecContext(ctx, `UPDATE email_change_requests SET current_code_hash='', new_code_hash=''
			WHERE user_id=$1 AND id=$2 AND status='pending' AND expires_at <= $3`, v.userID, v.requestID, now.UnixMicro()); err != nil {
			return err
		}
	}
	return nil
}
