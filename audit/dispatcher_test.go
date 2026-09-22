package audit

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeOutbox is a programmable OutboxStore: it hands the dispatcher a fixed
// batch and records what the dispatcher did with each row.
type fakeOutbox struct {
	mu        sync.Mutex
	rows      []OutboxRow
	successes []string
	failures  []struct {
		id   string
		next time.Time
		err  string
	}
	deadLettered []string
}

func (f *fakeOutbox) Insert(context.Context, string, *string, int, time.Time) error { return nil }
func (f *fakeOutbox) ClaimBatch(context.Context, string, int, time.Duration) ([]OutboxRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.rows
	f.rows = nil
	return rows, nil
}
func (f *fakeOutbox) MarkSuccess(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.successes = append(f.successes, id)
	return nil
}
func (f *fakeOutbox) MarkFailure(_ context.Context, id string, next time.Time, lastErr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = append(f.failures, struct {
		id   string
		next time.Time
		err  string
	}{id, next, lastErr})
	return nil
}
func (f *fakeOutbox) MarkDeadLetter(_ context.Context, id string, _ time.Time, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deadLettered = append(f.deadLettered, id)
	return nil
}
func (f *fakeOutbox) ReleaseClaim(context.Context, string) error { return nil }
func (f *fakeOutbox) SweepExpired(context.Context, time.Time, time.Duration, time.Duration) (int, int, error) {
	return 0, 0, nil
}
func (f *fakeOutbox) EvictOverCap(context.Context, int) (int, int, error) { return 0, 0, nil }
func (f *fakeOutbox) PurgeOrphans(context.Context, int) (int, error)      { return 0, nil }
func (f *fakeOutbox) CountPending(context.Context) (int, error)           { return 0, nil }
func (f *fakeOutbox) OldestPendingAge(context.Context, time.Time) (time.Duration, bool, error) {
	return 0, false, nil
}

func (f *fakeOutbox) snapshot() (succ []string, dead []string, fails int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.successes...), append([]string(nil), f.deadLettered...), len(f.failures)
}

func claimable(id string, attempts int) OutboxRow {
	return OutboxRow{
		EventID:  id,
		Attempts: attempts,
		Event: Event{
			ID:        id,
			Type:      EventLoginSuccess,
			Severity:  SeverityInfo,
			CreatedAt: time.Now().UTC(),
		},
	}
}

// TestDispatchOnce_SuccessDeletesObligation: a delivered batch removes its
// rows and counts nothing as dropped.
func TestDispatchOnce_SuccessDeletesObligation(t *testing.T) {
	fake := &fakeOutbox{rows: []OutboxRow{claimable("a", 1), claimable("b", 1)}}
	s := NewService(ServiceConfig{}, txSaverDB{}, &mockRecordStore{}, fake, nil)
	s.AddSink(noopSink{})

	s.dispatchOnce(context.Background(), "test-owner")

	succ, dead, fails := fake.snapshot()
	if len(succ) != 2 || len(dead) != 0 || fails != 0 {
		t.Fatalf("successes=%v dead=%v failures=%d, want 2/0/0", succ, dead, fails)
	}
}

// TestDispatchOnce_BackoffSchedulesRetry: a failure below MaxAttempts
// schedules the next attempt in the future with the exponential backoff.
func TestDispatchOnce_BackoffSchedulesRetry(t *testing.T) {
	fake := &fakeOutbox{rows: []OutboxRow{claimable("a", 1)}}
	s := NewService(ServiceConfig{MaxAttempts: 10}, txSaverDB{}, &mockRecordStore{}, fake, nil)
	s.AddSink(&failSink{err: errors.New("sink down")})

	s.dispatchOnce(context.Background(), "test-owner")

	_, dead, fails := fake.snapshot()
	if fails != 1 || len(dead) != 0 {
		t.Fatalf("failures=%d dead=%d, want 1 retry and 0 dead letters", fails, len(dead))
	}
	if got := fake.failures[0].next; !got.After(time.Now()) {
		t.Fatalf("next attempt %v must be in the future", got)
	}
}

// TestDispatchOnce_DeadLettersAtMaxAttempts: the terminal failure is marked,
// not deleted, so the evidence survives restarts.
func TestDispatchOnce_DeadLettersAtMaxAttempts(t *testing.T) {
	fake := &fakeOutbox{rows: []OutboxRow{claimable("a", 10)}}
	s := NewService(ServiceConfig{MaxAttempts: 10}, txSaverDB{}, &mockRecordStore{}, fake, nil)
	s.AddSink(&failSink{err: errors.New("sink down")})

	s.dispatchOnce(context.Background(), "test-owner")

	_, dead, fails := fake.snapshot()
	if fails != 0 || len(dead) != 1 {
		t.Fatalf("failures=%d dead=%v, want 0 retries and 1 dead letter", fails, dead)
	}
	if st := s.DeliveryStats(context.Background()); st.DeadLettered != 1 {
		t.Fatalf("dead_lettered = %d, want 1", st.DeadLettered)
	}
}

// TestDispatchOnce_StolenClaimCountsDuplicate: a row claimed away from a
// stalled claimer is a benign duplicate under at-least-once delivery, and
// must be visible so a too-short lease is diagnosable.
func TestDispatchOnce_StolenClaimCountsDuplicate(t *testing.T) {
	stolen := claimable("a", 2)
	stolen.Stolen = true
	fake := &fakeOutbox{rows: []OutboxRow{stolen}}
	s := NewService(ServiceConfig{}, txSaverDB{}, &mockRecordStore{}, fake, nil)
	s.AddSink(noopSink{})

	s.dispatchOnce(context.Background(), "test-owner")

	if st := s.DeliveryStats(context.Background()); st.DeliveryDuplicated != 1 {
		t.Fatalf("delivery_duplicated = %d, want 1", st.DeliveryDuplicated)
	}
}

// TestDeliveryStats_Gauges: the stats surface reports the store's gauges.
func TestDeliveryStats_Gauges(t *testing.T) {
	fake := &gaugeOutbox{pending: 7, age: 3 * time.Minute}
	s := NewService(ServiceConfig{}, txSaverDB{}, &mockRecordStore{}, fake, nil)

	st := s.DeliveryStats(context.Background())
	if st.Pending != 7 || !st.HasPending || st.OldestPendingAge != 3*time.Minute {
		t.Fatalf("stats = %+v, want pending=7 age=3m", st)
	}
}

type gaugeOutbox struct {
	fakeOutbox
	pending int
	age     time.Duration
}

func (g *gaugeOutbox) CountPending(context.Context) (int, error) { return g.pending, nil }
func (g *gaugeOutbox) OldestPendingAge(context.Context, time.Time) (time.Duration, bool, error) {
	return g.age, true, nil
}

var _ = net.ParseIP
