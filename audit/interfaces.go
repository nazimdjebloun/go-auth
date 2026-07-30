package audit

import "context"

type EventPublisher interface {
	Publish(ctx context.Context, event Event)
}

type EventSink interface {
	Handle(ctx context.Context, event Event) error
	HandleBatch(ctx context.Context, events []Event) error
}

type Cleaner interface {
	Cleanup(ctx context.Context, retentionDays int) (int, error)
}
