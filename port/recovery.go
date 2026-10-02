package port

import (
	"context"
	"time"
)

// RecoveryKind identifies a public email-based recovery request.
type RecoveryKind string

// RecoveryPasswordReset and RecoveryVerification select supported deliveries.
const (
	RecoveryPasswordReset RecoveryKind = "password_reset"
	RecoveryVerification  RecoveryKind = "verification"
)

// RecoveryRequest stores an address and operation, never a raw credential.
type RecoveryRequest struct {
	ID       string
	Kind     RecoveryKind
	Email    string
	Attempts int
	Owner    string
}

// RecoveryEnqueuer persists the same request shape for every supplied address.
type RecoveryEnqueuer interface {
	Enqueue(ctx context.Context, kind RecoveryKind, email string) error
}

// RecoveryStore owns leased, retryable recovery requests. Completion must be
// conditional on the unique claim owner, so an expired worker cannot acknowledge
// a request reclaimed by another instance.
type RecoveryStore interface {
	RecoveryEnqueuer
	Claim(ctx context.Context, now time.Time, lease time.Duration) (*RecoveryRequest, error)
	Complete(ctx context.Context, request RecoveryRequest, succeeded bool, now time.Time) error
	Prune(ctx context.Context, now time.Time) error
}
