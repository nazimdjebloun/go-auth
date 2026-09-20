package audit

import (
	"context"
	"time"
)

type EventSink interface {
	Handle(ctx context.Context, event Event) error
	HandleBatch(ctx context.Context, events []Event) error
}

// BatchDeliveryTimeBounder reports a sink's worst-case wall-clock time for
// one HandleBatch call. External sinks must implement this interface so
// startup can prove that ClaimLease outlives a complete delivery attempt.
// The bool is false when the sink has no finite bound.
type BatchDeliveryTimeBounder interface {
	MaxBatchDeliveryTime(batchSize int) (time.Duration, bool)
}

type Cleaner interface {
	Cleanup(ctx context.Context, retentionDays int) (int, error)
}
