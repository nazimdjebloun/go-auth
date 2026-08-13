package ratelimit

import (
	"testing"
	"time"
)

func TestDefaultRateLimitConfig_NotEmpty(t *testing.T) {
	cfg := DefaultRateLimitConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Default.Requests <= 0 {
		t.Error("expected default requests > 0")
	}
	if len(cfg.Routes) == 0 {
		t.Error("expected non-empty routes map")
	}
	if _, ok := cfg.Routes["POST /auth/login"]; !ok {
		t.Error("expected POST /auth/login in routes")
	}
	if _, ok := cfg.Routes["POST /auth/refresh"]; !ok {
		t.Error("expected POST /auth/refresh in routes")
	}
}

func TestMemoryStore_Increment_NewKey(t *testing.T) {
	s := NewMemoryStore().(*memoryStore)
	result, err := s.Increment("test-key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 1 {
		t.Errorf("expected count 1, got %d", result.Count)
	}
	if result.ResetAt.IsZero() {
		t.Error("expected non-zero reset time")
	}
}

func TestMemoryStore_Increment_ExistingKey(t *testing.T) {
	s := NewMemoryStore().(*memoryStore)
	_, _ = s.Increment("key", time.Minute)
	result, err := s.Increment("key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 2 {
		t.Errorf("expected count 2, got %d", result.Count)
	}
}

func TestMemoryStore_Increment_ExpiredBucket(t *testing.T) {
	s := NewMemoryStore().(*memoryStore)
	s.mu.Lock()
	s.buckets["key"] = &bucket{count: 5, resetAt: time.Now().Add(-time.Second)}
	s.mu.Unlock()

	result, err := s.Increment("key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 1 {
		t.Errorf("expected count 1 (new bucket), got %d", result.Count)
	}
}

func TestMemoryStore_Increment_IndependentKeys(t *testing.T) {
	s := NewMemoryStore().(*memoryStore)
	_, _ = s.Increment("a", time.Minute)
	_, _ = s.Increment("a", time.Minute)
	_, _ = s.Increment("b", time.Minute)

	ra, _ := s.Increment("a", time.Minute)
	if ra.Count != 3 {
		t.Errorf("expected key-a count 3, got %d", ra.Count)
	}
	rb, _ := s.Increment("b", time.Minute)
	if rb.Count != 2 {
		t.Errorf("expected key-b count 2, got %d", rb.Count)
	}
}

func TestMemoryStore_Reset(t *testing.T) {
	s := NewMemoryStore().(*memoryStore)
	_, _ = s.Increment("key", time.Minute)
	if err := s.Reset("key"); err != nil {
		t.Fatal(err)
	}
	result, err := s.Increment("key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 1 {
		t.Errorf("expected count 1 after reset, got %d", result.Count)
	}
}

func TestMemoryStore_StoreResultImplements(t *testing.T) {
	// Compile-time check: NewMemoryStore returns Store interface
	var _ Store = NewMemoryStore()
}

type fakeStore struct{}

func (fakeStore) Increment(_ string, _ time.Duration) (StoreResult, error) { return StoreResult{}, nil }
func (fakeStore) Reset(_ string) error                                     { return nil }

func TestIsDefaultStore(t *testing.T) {
	if !IsDefaultStore(NewMemoryStore()) {
		t.Error("expected NewMemoryStore() to be identified as the default store")
	}
	if IsDefaultStore(fakeStore{}) {
		t.Error("expected a distinct Store implementation to not be identified as the default store")
	}
}

// TestMemoryStore_Close_StopsCleanupGoroutine proves the cleanup goroutine
// actually exits, not just that Close doesn't panic: Close blocks on
// <-s.done, which only closes when cleanup's own select loop observes
// ctx.Done() and returns. If cleanup never exited, this call — and the
// test — would hang until the suite's own timeout, not return cleanly.
func TestMemoryStore_Close_StopsCleanupGoroutine(t *testing.T) {
	s := NewMemoryStore().(*memoryStore)

	done := make(chan struct{})
	go func() {
		s.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not return within 5s — cleanup goroutine likely did not exit")
	}
}

func TestMemoryStore_Close_SafeAfterClose(t *testing.T) {
	s := NewMemoryStore().(*memoryStore)
	s.Close()

	// Increment/Reset don't depend on cleanup running — the store stays
	// usable after Close, only pruning stops.
	if _, err := s.Increment("key", time.Minute); err != nil {
		t.Errorf("Increment after Close: %v", err)
	}
	if err := s.Reset("key"); err != nil {
		t.Errorf("Reset after Close: %v", err)
	}
}

func TestMemoryStore_ImplementsStoreCloser(t *testing.T) {
	var _ StoreCloser = NewMemoryStore().(*memoryStore)
}
