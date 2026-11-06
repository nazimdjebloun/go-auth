package port

import (
	"context"
	"time"
)

// SnapshotCache stores disposable, opaque snapshots. A miss returns nil, nil.
// Implementations must bound I/O, honor cancellation and preserve the supplied
// expiry. SQL remains authoritative; this is not a credential repository.
type SnapshotCache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, value []byte, ttl time.Duration) error
}
