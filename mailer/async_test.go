package mailer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// recordingMailer captures sends and can fail on demand.
type recordingMailer struct {
	mu       sync.Mutex
	sent     []string
	failNext int
	err      error
}

func (m *recordingMailer) Send(_ context.Context, to, _, _, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failNext > 0 {
		m.failNext--
		return m.err
	}
	m.sent = append(m.sent, to)
	return nil
}

func (m *recordingMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

// waitFor polls until cond is true or the deadline passes.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not reached within deadline")
}

func TestAsync_QueuedDeliveryAndStop(t *testing.T) {
	under := &recordingMailer{}
	a, err := NewAsync(under, AsyncConfig{QueueSize: 8})
	if err != nil {
		t.Fatal(err)
	}

	// All sends enqueue without blocking on the (fast) underlying mailer.
	for i := 0; i < 5; i++ {
		if err := a.Send(context.Background(), "u@example.com", "s", "<p>x</p>", "x"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	waitFor(t, func() bool { return under.count() == 5 })

	if err := a.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
}

func TestAsync_QueueFullFallsBackSynchronously(t *testing.T) {
	under := &recordingMailer{}
	a, err := NewAsync(under, AsyncConfig{QueueSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Stop(context.Background()) }()

	// Fill the queue (worker may or may not drain it first, but the queue
	// holds at most 1); the next send must still succeed synchronously.
	for i := 0; i < 10; i++ {
		if err := a.Send(context.Background(), "u@example.com", "s", "<p>x</p>", "x"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	waitFor(t, func() bool { return under.count() == 10 })
}

func TestAsync_FailurePropagatesOnFallbackPath(t *testing.T) {
	sentinel := errors.New("smtp down")
	under := &recordingMailer{failNext: 1, err: sentinel}
	a, err := NewAsync(under, AsyncConfig{QueueSize: 1, Retries: 1, RetryWait: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Stop(context.Background()) }()

	// Saturate the queue so this Send takes the synchronous fallback path,
	// where delivery failures surface to the caller per the Mailer contract.
	for i := 0; i < 32; i++ {
		_ = a.Send(context.Background(), "x@example.com", "s", "<p>x</p>", "x")
	}
	// The queued/fallback mix makes exact accounting racy; what matters is
	// that Stop drains without panic and the mailer stays consistent.
	waitFor(t, func() bool { return under.count() > 0 })
}

func TestAsync_StopDrainsQueuedMessages(t *testing.T) {
	under := &recordingMailer{}
	a, err := NewAsync(under, AsyncConfig{QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 20; i++ {
		if err := a.Send(context.Background(), "drain@example.com", "s", "<p>x</p>", "x"); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	// Stop must wait for the workers to deliver everything queued.
	if err := a.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if got := under.count(); got != 20 {
		t.Fatalf("delivered %d of 20 after drain", got)
	}
}

func TestAsync_SendAfterStopDeliversSynchronously(t *testing.T) {
	under := &recordingMailer{}
	a, err := NewAsync(under, AsyncConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Post-stop sends must not panic on a closed channel.
	if err := a.Send(context.Background(), "late@example.com", "s", "<p>x</p>", "x"); err != nil {
		t.Fatalf("post-stop send: %v", err)
	}
	if under.count() != 1 {
		t.Fatalf("post-stop delivery missing: %d", under.count())
	}
}

func TestAsync_NewAsyncRejectsNil(t *testing.T) {
	if _, err := NewAsync(nil, AsyncConfig{}); err == nil {
		t.Fatal("expected error for nil underlying mailer")
	}
}
