package sqlstore

import (
	"context"
	"time"
)

// Revoke applies a terminal state transition without writing a stale snapshot.
func (r *InviteRepository) Revoke(ctx context.Context, id string) (bool, error) {
	return affected(r.db.ExecContext(ctx, inviteRevokeQuery, id))
}

// RotateCode refreshes the exact still-resendable invite.
func (r *InviteRepository) RotateCode(ctx context.Context, id, expectedCode, newCode string, expiresAt time.Time) (bool, error) {
	return affected(r.db.ExecContext(ctx, inviteRotateCodeQuery, newCode, expiresAt, id, expectedCode))
}
