package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// ctxRecorderSink records whether the context it received for a batch was
// already canceled. Stop() cancels the worker context before workers drain,
// so a final flush that reuses that context hands sinks a dead context and
// every context-aware write fails.
type ctxRecorderSink struct {
	mu      sync.Mutex
	ctxErrs []error
}

func (s *ctxRecorderSink) Handle(ctx context.Context, event Event) error {
	return s.HandleBatch(ctx, []Event{event})
}

func (s *ctxRecorderSink) HandleBatch(ctx context.Context, events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ctxErrs = append(s.ctxErrs, ctx.Err())
	return nil
}

func (s *ctxRecorderSink) recorded() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]error, len(s.ctxErrs))
	copy(out, s.ctxErrs)
	return out
}

func TestStopFlushesFinalBatchWithLiveContext(t *testing.T) {
	svc := NewAuditService(AuditServiceConfig{QueueSize: 10, Workers: 1, BatchSize: 10, FlushInterval: time.Hour}, nil)
	sink := &ctxRecorderSink{}
	svc.AddSink(sink)

	svc.Start(context.Background())
	svc.Publish(context.Background(), NewAdminEvent(EventAdminUserBanned, "actor", "target"))

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := svc.Stop(stopCtx); err != nil {
		t.Fatalf("Stop returned error: %v", err)
	}

	errs := sink.recorded()
	if len(errs) == 0 {
		t.Fatal("sink never received a batch")
	}
	for i, err := range errs {
		if !errors.Is(err, context.Canceled) && err != nil {
			t.Fatalf("batch %d received unexpected context error: %v", i, err)
		}
		if errors.Is(err, context.Canceled) {
			t.Fatalf("batch %d was flushed with a canceled context — final drain writes would fail", i)
		}
	}
}
