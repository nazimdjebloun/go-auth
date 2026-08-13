package ratelimit

import (
	"context"
	"sync"
	"time"
)

type memoryStore struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	cancel  context.CancelFunc
	done    chan struct{}
}

type bucket struct {
	count   int
	resetAt time.Time
}

func NewMemoryStore() Store {
	ctx, cancel := context.WithCancel(context.Background())
	s := &memoryStore{
		buckets: make(map[string]*bucket),
		cancel:  cancel,
		done:    make(chan struct{}),
	}
	go s.cleanup(ctx)
	return s
}

// StoreCloser is an optional capability a Store can implement to release
// background resources (e.g. a cleanup goroutine). It's a separate
// interface from Store, not an addition to it, so a consumer-provided Store
// (Redis-backed or otherwise) that has nothing to close isn't forced to grow
// a no-op method — Auth.Close checks for it via a type assertion.
type StoreCloser interface {
	Close()
}

var _ StoreCloser = (*memoryStore)(nil)

// Close stops the background cleanup goroutine. Safe to call once; the
// store remains readable/writable after Close (Increment/Reset don't depend
// on cleanup running), it just stops pruning expired buckets.
func (s *memoryStore) Close() {
	s.cancel()
	<-s.done
}

// IsDefaultStore reports whether s is a Store returned by NewMemoryStore —
// used by Auth.New to warn that rate limiting doesn't share state across
// instances. This matches by type, not by construction site: a store built
// via an explicit WithRateLimitStore(ratelimit.NewMemoryStore()) matches
// too, since the underlying multi-instance caveat is identical either way —
// only a genuinely different Store implementation (e.g. Redis-backed)
// avoids the warning.
func IsDefaultStore(s Store) bool {
	_, ok := s.(*memoryStore)
	return ok
}

func (s *memoryStore) Increment(key string, window time.Duration) (StoreResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	b, ok := s.buckets[key]
	if !ok || now.After(b.resetAt) {
		b = &bucket{resetAt: now.Add(window)}
		s.buckets[key] = b
	}
	b.count++
	return StoreResult{Count: b.count, ResetAt: b.resetAt}, nil
}

func (s *memoryStore) Reset(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.buckets, key)
	return nil
}

func (s *memoryStore) cleanup(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for k, b := range s.buckets {
				if now.After(b.resetAt) {
					delete(s.buckets, k)
				}
			}
			s.mu.Unlock()
		}
	}
}
