package port

import (
	"context"
	"time"
)

// UserNameUpdater changes only name and updated_at. False means the user
// no longer exists. This optional capability avoids stale snapshot writes.
type UserNameUpdater interface {
	UpdateName(ctx context.Context, userID, name string, updatedAt time.Time) (bool, error)
}

// UserEmailVerifier sets only verification fields and updated_at, provided
// the stored email still exactly matches expectedEmail. False means the user
// is absent or the email changed. Implementations must honor transaction contexts.
type UserEmailVerifier interface {
	VerifyEmailIfMatches(ctx context.Context, userID, expectedEmail string, verifiedAt time.Time) (bool, error)
}
