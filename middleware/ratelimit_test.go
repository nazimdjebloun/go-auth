package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// TestRateLimit_WildcardMatch_MidPathSegment is a regression test for a bug
// where a Routes key with a "*" anywhere but the very end (e.g.
// "POST /auth/orgs/*/invites") never matched any real request — the old
// matcher only treated a key as a pattern when it literally ended in "/*",
// and even then matched by string prefix rather than by segment. A route
// like this silently fell back to Default instead of its configured rate.
func TestRateLimit_WildcardMatch_MidPathSegment(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 100, Window: time.Minute},
		Routes: map[string]ratelimit.Rate{
			"POST /auth/orgs/*/invites": {Requests: 1, Window: time.Minute},
		},
	}
	rl := RateLimit(cfg)

	var calls int
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	var last *httptest.ResponseRecorder
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/auth/orgs/org_abc123/invites", nil)
		req.RemoteAddr = "192.0.2.50:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		last = rec
	}

	if calls != 1 {
		t.Fatalf("expected the tight 1/min limit to trip on the second request, got %d allowed calls", calls)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 once the mid-path wildcard route's own limit is exceeded, got %d", last.Code)
	}
}

// TestRateLimit_WildcardMatch_TrailingSegment covers the case the old
// matcher did handle (a key ending in "/*"), now going through the same
// segment-based matcher as every other wildcard route.
func TestRateLimit_WildcardMatch_TrailingSegment(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 100, Window: time.Minute},
		Routes: map[string]ratelimit.Rate{
			"GET /auth/orgs/*": {Requests: 1, Window: time.Minute},
		},
	}
	rl := RateLimit(cfg)

	req := httptest.NewRequest("GET", "/auth/orgs/org_abc123", nil)
	req.RemoteAddr = "192.0.2.50:1234"
	rec := httptest.NewRecorder()
	rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected first request to pass, got %d", rec.Code)
	}
}

// TestRateLimit_WildcardMatch_DoesNotMatchDeeperPath is the flip side of
// the old bug: since matching is now exact by segment count, a wildcard
// route no longer silently swallows every deeper path under it. A route
// one level deeper than the pattern must have its own entry or fall to
// Default — it must not inherit the shallower pattern's rate.
func TestRateLimit_WildcardMatch_DoesNotMatchDeeperPath(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 5, Window: time.Minute},
		Routes: map[string]ratelimit.Rate{
			"GET /auth/orgs/*": {Requests: 1, Window: time.Minute},
		},
	}
	rl := RateLimit(cfg)

	var calls int
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	// Two requests to the one-segment-deeper path should both pass under
	// Default (5/min), not trip the one-segment pattern's 1/min limit.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/auth/orgs/org_abc123/members", nil)
		req.RemoteAddr = "192.0.2.50:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 under Default, got %d", i, rec.Code)
		}
	}
	if calls != 2 {
		t.Errorf("expected both requests to reach the handler, got %d calls", calls)
	}
}

func TestRateLimit_NoMatch_FallsBackToDefault(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 1, Window: time.Minute},
		Routes: map[string]ratelimit.Rate{
			"POST /auth/login": {Requests: 100, Window: time.Minute},
		},
	}
	rl := RateLimit(cfg)

	var last *httptest.ResponseRecorder
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/auth/unlisted-route", nil)
		req.RemoteAddr = "192.0.2.50:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		last = rec
	}

	if last.Code != http.StatusTooManyRequests {
		t.Errorf("expected Default's 1/min to trip on an unlisted route, got %d", last.Code)
	}
}
