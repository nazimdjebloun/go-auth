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
	called := false
	a, _ := saturatedAsync(t, 0, func(context.Context) error {
		called = true
		return nil
	})
	if err := a.Send(t.Context(), "fallback", "s", "html", "text"); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("full queue did not deliver synchronously")
	}
}

func TestAsync_FailurePropagatesOnFallbackPath(t *testing.T) {
	sentinel := errors.New("smtp down")
	attempts := 0
	a, _ := saturatedAsync(t, 2, func(context.Context) error {
		attempts++
		return sentinel
	})
	if err := a.Send(t.Context(), "fallback", "s", "html", "text"); !errors.Is(err, sentinel) {
		t.Fatalf("fallback error = %v, want %v", err, sentinel)
	}
	if attempts != 3 {
		t.Fatalf("fallback attempted %d sends, want 3", attempts)
	}
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

type asyncMailerFunc func(context.Context, string, string, string, string) error

func (f asyncMailerFunc) Send(ctx context.Context, to, subject, html, text string) error {
	return f(ctx, to, subject, html, text)
}

// Hold the only worker inside Send, then fill the only queue slot. The next
// Send must use the fallback, regardless of scheduling or machine speed.
func saturatedAsync(t *testing.T, retries int, fallback func(context.Context) error) (*Async, func()) {
	t.Helper()
	started, release := make(chan struct{}), make(chan struct{})
	delivered := make(chan string, 2)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	under := asyncMailerFunc(func(ctx context.Context, to, _, _, _ string) error {
		switch to {
		case "active":
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		case "fallback":
			return fallback(ctx)
		}
		delivered <- to
		return nil
	})
	a, err := NewAsync(under, AsyncConfig{QueueSize: 1, Retries: retries, RetryWait: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		unblock()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := a.Stop(ctx); err != nil {
			t.Errorf("cleanup drain: %v", err)
		}
		if len(delivered) != 2 {
			t.Errorf("delivered %d messages, want active and queued", len(delivered))
		}
	})
	if err := a.Send(t.Context(), "active", "s", "html", "text"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not start")
	}
	if err := a.Send(t.Context(), "queued", "s", "html", "text"); err != nil {
		t.Fatal(err)
	}
	return a, unblock
}

func TestAsync_NewAsyncRejectsNegativeRetries(t *testing.T) {
	if a, err := NewAsync(&recordingMailer{}, AsyncConfig{Retries: -1}); err == nil || a != nil {
		t.Fatalf("negative retries returned mailer %v, error %v", a, err)
	}
}

func TestAsync_ZeroRetriesStillAttemptsDelivery(t *testing.T) {
	sentinel := errors.New("smtp down")
	attempts := 0
	a, _ := saturatedAsync(t, 0, func(context.Context) error {
		attempts++
		return sentinel
	})
	if err := a.Send(t.Context(), "fallback", "s", "html", "text"); !errors.Is(err, sentinel) || attempts != 1 {
		t.Fatalf("zero retries made %d attempts, error %v", attempts, err)
	}
}

func TestAsync_StopCancellationLeavesWorkersDraining(t *testing.T) {
	a, unblock := saturatedAsync(t, 0, func(context.Context) error { return nil })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for range 5 {
		if err := a.Stop(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled stop: %v", err)
		}
	}
	select {
	case <-a.done:
		t.Fatal("drain finished while the underlying send was blocked")
	default:
	}
	unblock()
	waitCtx, waitCancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer waitCancel()
	if err := a.Stop(waitCtx); err != nil {
		t.Fatal(err)
	}
	if len(a.queue) != 0 {
		t.Fatal("canceled stop abandoned queued mail")
	}
}

func TestAsync_RetriesQueuedDelivery(t *testing.T) {
	under := &recordingMailer{failNext: 2, err: errors.New("temporary SMTP failure")}
	a, err := NewAsync(under, AsyncConfig{Retries: 2, RetryWait: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(t.Context(), "retry@example.com", "s", "html", "text"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := a.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if under.count() != 1 {
		t.Fatal("queued mail was not delivered after retrying the failures")
	}
}

func TestAsync_ConcurrentSendAndStop(t *testing.T) {
	under := &recordingMailer{}
	a, err := NewAsync(under, AsyncConfig{QueueSize: 1, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for range 64 {
		wg.Go(func() {
			if err := a.Send(ctx, "user@example.com", "s", "html", "text"); err != nil {
				t.Errorf("send: %v", err)
			}
		})
	}
	for range 8 {
		wg.Go(func() {
			if err := a.Stop(ctx); err != nil {
				t.Errorf("stop: %v", err)
			}
		})
	}
	wg.Wait()
	if err := a.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if got := under.count(); got != 64 {
		t.Fatalf("concurrent shutdown delivered %d of 64 messages", got)
	}
}
