package ratelimit

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T, opts ...MemoryStoreOption) *memoryStore {
	t.Helper()
	s := NewMemoryStore(opts...).(*memoryStore)
	t.Cleanup(s.Close)
	return s
}

func perMinute(n int) Rate { return Rate{Requests: n, Window: time.Minute} }

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

// TestDefaultRateLimitConfig_LeavesStoreNil pins the fix for a goroutine
// leak: every WithRateLimit* option calls this function to lazily seed a
// config, so a Store constructed here started a cleanup goroutine per option
// call that nothing owned and Close could never reach.
func TestDefaultRateLimitConfig_LeavesStoreNil(t *testing.T) {
	if got := DefaultRateLimitConfig().Store; got != nil {
		t.Errorf("expected Store to be filled in lazily by the consumer, got %T", got)
	}
}

func TestMemoryStore_Allow_NewKey(t *testing.T) {
	s := newTestStore(t)
	res, err := s.Allow(context.Background(), "test-key", perMinute(5))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed {
		t.Error("expected the first request in a window to be allowed")
	}
	if res.Remaining != 4 {
		t.Errorf("expected 4 remaining, got %d", res.Remaining)
	}
	if res.ResetAt.IsZero() {
		t.Error("expected non-zero reset time")
	}
}

func TestMemoryStore_Allow_TripsAtLimit(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 1; i <= 3; i++ {
		res, _ := s.Allow(ctx, "key", perMinute(3))
		if !res.Allowed {
			t.Fatalf("request %d: expected allowed under a 3/min limit", i)
		}
	}
	res, _ := s.Allow(ctx, "key", perMinute(3))
	if res.Allowed {
		t.Error("expected the 4th request to be denied under a 3/min limit")
	}
	if res.Remaining != 0 {
		t.Errorf("expected 0 remaining once over the limit, got %d", res.Remaining)
	}
}

func TestMemoryStore_Allow_ExpiredBucketStartsFresh(t *testing.T) {
	s := newTestStore(t)
	sh := s.shards[shardIndex("key")]
	sh.mu.Lock()
	sh.buckets["key"] = &bucket{count: 5, limit: 5, resetAt: time.Now().Add(-time.Second)}
	sh.mu.Unlock()

	res, err := s.Allow(context.Background(), "key", perMinute(5))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed || res.Remaining != 4 {
		t.Errorf("expected a fresh window after expiry, got allowed=%v remaining=%d", res.Allowed, res.Remaining)
	}
}

func TestMemoryStore_Allow_IndependentKeys(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, _ = s.Allow(ctx, "a", perMinute(5))
	_, _ = s.Allow(ctx, "a", perMinute(5))
	_, _ = s.Allow(ctx, "b", perMinute(5))

	ra, _ := s.Allow(ctx, "a", perMinute(5))
	if ra.Remaining != 2 {
		t.Errorf("expected key-a to have 2 remaining after 3 calls, got %d", ra.Remaining)
	}
	rb, _ := s.Allow(ctx, "b", perMinute(5))
	if rb.Remaining != 3 {
		t.Errorf("expected key-b to have 3 remaining after 2 calls, got %d", rb.Remaining)
	}
}

// TestMemoryStore_Sweep_RemovesExpired covers the periodic prune directly
// rather than waiting on the ticker. Nothing exercised this path before, so
// a sweep that silently removed nothing — or removed live counters — would
// have passed the suite.
func TestMemoryStore_Sweep_RemovesExpired(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// A long window that must survive, and short ones that must not.
	if _, err := s.Allow(ctx, "live", Rate{Requests: 5, Window: time.Hour}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if _, err := s.Allow(ctx, "dead-"+strconv.Itoa(i), Rate{Requests: 5, Window: time.Millisecond}); err != nil {
			t.Fatal(err)
		}
	}

	s.sweep(time.Now().Add(time.Second))

	st := s.Stats()
	if st.Entries != 1 {
		t.Errorf("expected only the live counter to survive the sweep, got %d entries", st.Entries)
	}
	if st.Expired < 20 {
		t.Errorf("expected at least 20 expirations recorded, got %d", st.Expired)
	}
}

// TestMemoryStore_StaysBoundedUnderKeyFlood is the memory-safety test. The
// old store held one map per process with no cap, so a caller able to mint
// unique keys grew it until the process died. Capacity here is a hard
// ceiling, not a target.
func TestMemoryStore_StaysBoundedUnderKeyFlood(t *testing.T) {
	const capacity = 320 // 10 per shard
	s := newTestStore(t, WithMaxEntries(capacity))
	ctx := context.Background()

	for i := 0; i < 50_000; i++ {
		if _, err := s.Allow(ctx, fmt.Sprintf("flood-%d", i), Rate{Requests: 100, Window: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}

	st := s.Stats()
	if st.Entries > capacity {
		t.Errorf("store grew past its cap: %d entries with capacity %d", st.Entries, capacity)
	}
	if st.Evictions == 0 {
		t.Error("expected evictions to be recorded once the store filled")
	}
}

// TestMemoryStore_EvictsHighHeadroomFirst pins the eviction *policy*, which
// is a security property rather than a tuning detail: any ranking an
// attacker can steer is a rate-limit bypass. A counter close to tripping
// (little headroom) must outlive the single-hit junk counters a flood
// creates, so that flooding evicts the flood rather than the login limit
// it wants forgotten.
func TestMemoryStore_EvictsHighHeadroomFirst(t *testing.T) {
	// 10 entries per shard: enough that the K=8 sample always sees several
	// candidates, so the victim is a real choice rather than the only
	// occupant.
	s := newTestStore(t, WithMaxEntries(shardCount*10))
	ctx := context.Background()

	// A login counter one request away from tripping.
	const hot = "POST /auth/login:198.51.100.7"
	for i := 0; i < 5; i++ {
		if _, err := s.Allow(ctx, hot, perMinute(5)); err != nil {
			t.Fatal(err)
		}
	}

	// Flood the shard the hot key lives in with fresh, wide-open counters.
	hotShard := shardIndex(hot)
	planted := 0
	for i := 0; planted < 200; i++ {
		k := fmt.Sprintf("decoy-%d", i)
		if shardIndex(k) != hotShard {
			continue
		}
		if _, err := s.Allow(ctx, k, Rate{Requests: 1000, Window: time.Hour}); err != nil {
			t.Fatal(err)
		}
		planted++
	}

	s.shards[hotShard].mu.Lock()
	_, survived := s.shards[hotShard].buckets[hot]
	s.shards[hotShard].mu.Unlock()

	if !survived {
		t.Error("the near-limit login counter was evicted by a flood of wide-open decoys — the eviction policy is steerable, which makes it a rate-limit bypass")
	}
}

// TestMemoryStore_StatsCapacityReportsEnforcedCeiling pins that Capacity is
// the ceiling the store honours, not the number handed to WithMaxEntries.
// The cap is enforced per shard, so a request that doesn't divide by
// shardCount is rounded down and one below shardCount is floored at one per
// shard. Echoing the request back would make the one field an operator uses
// to reason about occupancy report a number the store never enforces.
func TestMemoryStore_StatsCapacityReportsEnforcedCeiling(t *testing.T) {
	tests := []struct {
		requested int
		want      int
	}{
		{defaultMaxEntries, defaultMaxEntries}, // divides evenly
		{shardCount * 10, shardCount * 10},     // divides evenly
		{shardCount*10 + 31, shardCount * 10},  // rounded down
		{5, shardCount},                        // floored at one per shard
	}
	for _, tt := range tests {
		s := newTestStore(t, WithMaxEntries(tt.requested))
		if got := s.Stats().Capacity; got != tt.want {
			t.Errorf("WithMaxEntries(%d): Capacity = %d, want the enforced ceiling %d", tt.requested, got, tt.want)
		}
	}
}

func TestMemoryStore_WithoutEviction_KeepsEverything(t *testing.T) {
	s := newTestStore(t, WithoutEviction())
	ctx := context.Background()

	for i := 0; i < 5_000; i++ {
		if _, err := s.Allow(ctx, fmt.Sprintf("k-%d", i), Rate{Requests: 5, Window: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}

	st := s.Stats()
	if st.Entries != 5_000 {
		t.Errorf("expected all 5000 counters retained without eviction, got %d", st.Entries)
	}
	if st.Capacity != 0 {
		t.Errorf("expected Capacity 0 to report an uncapped store, got %d", st.Capacity)
	}
	if st.Evictions != 0 {
		t.Errorf("expected no evictions in an uncapped store, got %d", st.Evictions)
	}
}

// TestMemoryStore_ConcurrentAllow checks the sharded counters under -race
// and, more importantly, that sharding didn't cost exactness: N goroutines
// hammering one key must produce exactly N increments, no more.
func TestMemoryStore_ConcurrentAllow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const (
		goroutines = 32
		perG       = 100
		total      = goroutines * perG
	)

	var wg sync.WaitGroup
	allowed := make([]int, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				res, err := s.Allow(ctx, "shared", Rate{Requests: total / 2, Window: time.Hour})
				if err != nil {
					t.Error(err)
					return
				}
				if res.Allowed {
					allowed[g]++
				}
			}
		}(g)
	}
	wg.Wait()

	sum := 0
	for _, n := range allowed {
		sum += n
	}
	if sum != total/2 {
		t.Errorf("expected exactly %d of %d concurrent requests to be allowed, got %d", total/2, total, sum)
	}
}

func TestMemoryStore_StoreResultImplements(t *testing.T) {
	// Compile-time check: NewMemoryStore returns Store interface
	var _ Store = NewMemoryStore()
}

type fakeStore struct{}

func (fakeStore) Allow(context.Context, string, Rate) (Result, error) { return Result{}, nil }

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

	// Allow doesn't depend on cleanup running — the store stays usable
	// after Close, only pruning stops.
	if _, err := s.Allow(context.Background(), "key", perMinute(5)); err != nil {
		t.Errorf("Allow after Close: %v", err)
	}
}

func TestMemoryStore_ImplementsStoreCloser(t *testing.T) {
	var _ StoreCloser = NewMemoryStore().(*memoryStore)
}
