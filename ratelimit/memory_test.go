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
