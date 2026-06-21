package ratelimit

import (
	"sync"
	"time"
)

type memoryStore struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count   int
	resetAt time.Time
}

func NewMemoryStore() Store {
	s := &memoryStore{buckets: make(map[string]*bucket)}
	go s.cleanup()
	return s
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

func (s *memoryStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
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
