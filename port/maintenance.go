package port

import (
	"context"
	"time"
)

// ExpiredRowDeleter removes at most limit rows that expired before the cutoff
// and reports how many rows were deleted. Storage is SQL-only, so the
// built-in session and token repositories always implement it; the
// maintenance runner wires both directly.
//
// Implementations must be safe to call concurrently and must never delete a
// row that is still usable — the caller passes a cutoff already set back by
// the configured grace period, and an implementation must not extend it.
type ExpiredRowDeleter interface {
	DeleteExpiredBatch(ctx context.Context, cutoff time.Time, limit int) (int, error)
}
