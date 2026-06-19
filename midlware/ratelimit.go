package midlware

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

type rateEntry struct {
	count   int
	resetAt time.Time
}

type memoryStore struct {
	mu    sync.Mutex
	store map[string]*rateEntry
}

func (s *memoryStore) Increment(key string, window time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.store[key]
	if !ok || time.Now().After(entry.resetAt) {
		entry = &rateEntry{count: 0, resetAt: time.Now().Add(window)}
		s.store[key] = entry
	}

	entry.count++
	return entry.count, nil
}

func (s *memoryStore) Reset(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, key)
	return nil
}

func RateLimit(cfg *port.RateLimitConfig) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}

	var store port.RateLimitStore
	if cfg.Store != nil {
		store = cfg.Store
	} else {
		store = &memoryStore{store: make(map[string]*rateEntry)}
	}

	trusted := make(map[string]bool)
	for _, ip := range cfg.TrustedIPs {
		trusted[ip] = true
	}

	disabled := make(map[string]bool)
	for _, path := range cfg.DisabledPaths {
		disabled[path] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if trusted[r.RemoteAddr] {
				next.ServeHTTP(w, r)
				return
			}

			if disabled[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			key := r.Method + " " + r.URL.Path
			rate, ok := cfg.Endpoints[key]
			if !ok {
				rate = cfg.Default
			}

			if rate.Requests <= 0 {
				next.ServeHTTP(w, r)
				return
			}

			clientKey := r.RemoteAddr + ":" + key
			count, err := store.Increment(clientKey, rate.Window)
			if err != nil {
				log.Printf("rate limit error: %v", err)
				next.ServeHTTP(w, r)
				return
			}

			if count > rate.Requests {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"error":   "rate_limit_exceeded",
					"message": "Too many requests, please try again later",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
