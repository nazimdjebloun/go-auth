package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/id"
	"github.com/nazimdjebloun/go-auth/port"
)

// RecoveryRepository persists public requests independently of account lookup.
type RecoveryRepository struct{ db *DB }

// NewRecoveryRepository uses the pre-applied recovery_requests schema.
func NewRecoveryRepository(db *DB) *RecoveryRepository { return &RecoveryRepository{db: db} }

var _ port.RecoveryStore = (*RecoveryRepository)(nil)

// Enqueue writes only caller input, without consulting account state.
func (r *RecoveryRepository) Enqueue(ctx context.Context, kind port.RecoveryKind, email string) error {
	now := time.Now().Unix()
	_, err := r.db.ExecContext(ctx, `INSERT INTO recovery_requests
		(id, kind, email, attempts, available_at, lease_until, claim_owner, dead_lettered, created_at)
		VALUES ($1, $2, $3, 0, $4, 0, '', 0, $5)`, id.New(), kind, email, now, now)
	return err
}

// Claim guards acquisition with an atomic update so competing instances cannot
// both own a live lease. Every acquired lease spends one attempt.
func (r *RecoveryRepository) Claim(ctx context.Context, now time.Time, lease time.Duration) (*port.RecoveryRequest, error) {
	var request port.RecoveryRequest
	err := r.db.QueryRowContext(ctx, `SELECT id, kind, email, attempts FROM recovery_requests
		WHERE dead_lettered = 0 AND available_at <= $1 AND lease_until <= $2
		AND created_at > $3 ORDER BY available_at, id LIMIT 1`, now.Unix(), now.Unix(), now.Add(-24*time.Hour).Unix()).
		Scan(&request.ID, &request.Kind, &request.Email, &request.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	request.Owner = id.New()
	res, err := r.db.ExecContext(ctx, `UPDATE recovery_requests SET claim_owner = $1, lease_until = $2,
		attempts = attempts + 1 WHERE id = $3 AND dead_lettered = 0 AND available_at <= $4
		AND lease_until <= $5`, request.Owner, now.Add(lease).Unix(), request.ID, now.Unix(), now.Unix())
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil || n == 0 {
		return nil, err
	}
	// Read the actual counter after the guarded increment. Do not infer it
	// from a snapshot that another worker could have processed in the meantime.
	err = r.db.QueryRowContext(ctx, `SELECT attempts FROM recovery_requests WHERE id = $1 AND claim_owner = $2`,
		request.ID, request.Owner).Scan(&request.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &request, nil
}

// Complete acknowledges only the supplied claim owner, deleting success or
// scheduling failure without changing a newer worker's claim.
func (r *RecoveryRepository) Complete(ctx context.Context, request port.RecoveryRequest, succeeded bool, now time.Time) error {
	if succeeded {
		_, err := r.db.ExecContext(ctx, `DELETE FROM recovery_requests WHERE id = $1 AND claim_owner = $2`, request.ID, request.Owner)
		return err
	}
	dead := 0
	if request.Attempts >= 5 {
		dead = 1
	}
	// Ten-second exponential backoff; attempts above the budget are never sent.
	delay := 10 * time.Second * time.Duration(1<<max(0, min(request.Attempts-1, 4)))
	_, err := r.db.ExecContext(ctx, `UPDATE recovery_requests SET available_at = $1,
		lease_until = 0, claim_owner = '', dead_lettered = $2 WHERE id = $3 AND claim_owner = $4`,
		now.Add(delay).Unix(), dead, request.ID, request.Owner)
	return err
}

// Prune enforces pending and dead-letter retention while preserving live leases.
func (r *RecoveryRepository) Prune(ctx context.Context, now time.Time) error {
	// Keep failed requests for seven days as operational evidence. Undelivered
	// requests stop being eligible after one day, so a restart cannot send an
	// arbitrarily old recovery email. Never remove an actively leased request.
	_, err := r.db.ExecContext(ctx, `DELETE FROM recovery_requests WHERE lease_until <= $1
		AND ((dead_lettered = 0 AND created_at <= $2) OR (dead_lettered = 1 AND created_at <= $3))`,
		now.Unix(), now.Add(-24*time.Hour).Unix(), now.Add(-7*24*time.Hour).Unix())
	return err
}
