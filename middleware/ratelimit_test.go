package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// TestRateLimit_PathParamCannotMintFreshCounters is the regression test for
// the bug that made the store unbounded and the limit unenforceable at the
// same time.
//
// Counters used to be keyed on r.URL.Path. Fourteen of the built-in
// rate-limited routes carry a path parameter, so varying that segment gave a
// caller a brand-new counter on every request: the limit never tripped
// (no key ever repeated) and the map grew for as long as the requests kept
// coming — an unauthenticated memory-exhaustion primitive, since rate
// limiting sits outside the auth middleware by design.
func TestRateLimit_PathParamCannotMintFreshCounters(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 1000, Window: time.Minute},
		Routes: map[string]ratelimit.Rate{
			"POST /auth/orgs/*/invites": {Requests: 3, Window: time.Minute},
		},
	}
	rl := RateLimit(cfg)

	var calls int
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	var last *httptest.ResponseRecorder
	for i := 0; i < 20; i++ {
		// A different org id every time — and a long one, the shape that
		// used to turn each request into ~1 KB of permanent map key.
		org := fmt.Sprintf("org-%d-%s", i, strings.Repeat("x", 512))
		req := httptest.NewRequest("POST", "/auth/orgs/"+org+"/invites", nil)
		req.RemoteAddr = "192.0.2.50:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		last = rec
	}

	if calls != 3 {
		t.Errorf("expected the 3/min limit to hold across varying path params, got %d allowed calls", calls)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after the limit, got %d", last.Code)
	}
}

// TestRateLimit_JunkForwardedHeaderCannotMintFreshCounters covers the second
// door into the same room. extractIP used to return an unparseable header
// value verbatim, so behind a proxy that forwards X-Forwarded-For without
// validating it, the *IP* half of the key became attacker-controlled — the
// route-pattern fix alone doesn't close this.
func TestRateLimit_JunkForwardedHeaderCannotMintFreshCounters(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:         true,
		IPv6Subnet:      64,
		IPAddressHeader: "X-Forwarded-For",
		TrustedIPs:      []string{"192.168.1.1"},
		Default:         ratelimit.Rate{Requests: 3, Window: time.Minute},
	}
	rl := RateLimit(cfg)

	var calls int
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest("POST", "/auth/login", nil)
		req.RemoteAddr = "192.168.1.1:34567" // trusted proxy
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("junk-%d-%s", i, strings.Repeat("z", 256)))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
	}

	if calls != 3 {
		t.Errorf("expected the 3/min limit to hold across junk header values, got %d allowed calls", calls)
	}
}

// TestRateLimit_OversizedMethodCannotMintFreshCounters is the third door
// into the unbounded-key-space room, and the one an entry cap doesn't close.
//
// net/http checks that a method is made of HTTP token bytes, not how many
// there are, so a ~1 MB method is accepted and reaches the handler verbatim.
// Concatenated into a key, that makes the store's 100k-entry ceiling a
// byte-budget of 100 GB: the count is bounded, the size of each entry isn't.
// Folding the method to a fixed set bounds both.
func TestRateLimit_OversizedMethodCannotMintFreshCounters(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 3, Window: time.Minute},
	}
	rl := RateLimit(cfg)

	var calls int
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 20; i++ {
		// A distinct, oversized, otherwise-valid method every time.
		method := fmt.Sprintf("X%d%s", i, strings.Repeat("A", 4096))
		req := httptest.NewRequest(method, "/whatever", nil)
		req.RemoteAddr = "192.0.2.50:1234"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	if calls != 3 {
		t.Errorf("expected the 3/min limit to hold across varying methods, got %d allowed calls", calls)
	}
}

// TestRateLimit_StandardMethodsKeepSeparateCounters is the constraint the
// fold has to respect: GET /x and DELETE /x are different routes with
// different limits in the built-in table, so they must not share a counter.
func TestRateLimit_StandardMethodsKeepSeparateCounters(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 1, Window: time.Minute},
	}
	rl := RateLimit(cfg)

	var calls int
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	methods := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "CONNECT", "OPTIONS", "TRACE"}
	for _, m := range methods {
		req := httptest.NewRequest(m, "/whatever", nil)
		req.RemoteAddr = "192.0.2.50:1234"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	if calls != len(methods) {
		t.Errorf("expected each standard method to get its own 1/min budget (%d total), got %d", len(methods), calls)
	}
}

// TestRateLimit_DistinctClientsStayDistinct is the other half of the keying
// change: collapsing paths onto their pattern must not collapse *clients*
// onto each other. Each IP keeps its own budget.
func TestRateLimit_DistinctClientsStayDistinct(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 2, Window: time.Minute},
	}
	rl := RateLimit(cfg)

	var calls int
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		for _, ip := range []string{"192.0.2.10:1", "192.0.2.11:1", "198.51.100.3:1"} {
			req := httptest.NewRequest("GET", "/whatever", nil)
			req.RemoteAddr = ip
			h.ServeHTTP(httptest.NewRecorder(), req)
		}
	}

	if calls != 6 { // 2 allowed per IP, 3 IPs
		t.Errorf("expected each of 3 clients to get its own 2/min budget (6 total), got %d", calls)
	}
}

// TestRateLimit_ServeMuxPatternKeepsRoutesSeparate covers the fallback for
// consumer routes not listed in Routes: net/http's ServeMux fills in
// r.Pattern (Go 1.23+), so they still get one counter per route rather than
// sharing the single fallback counter.
func TestRateLimit_ServeMuxPatternKeepsRoutesSeparate(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 2, Window: time.Minute},
	}
	rl := RateLimit(cfg)

	var calls int
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	mux := http.NewServeMux()
	mux.Handle("GET /widgets/{id}", h)
	mux.Handle("GET /gadgets/{id}", h)

	for i := 0; i < 4; i++ {
		for _, path := range []string{"/widgets/a", "/widgets/b", "/gadgets/c"} {
			req := httptest.NewRequest("GET", path, nil)
			req.RemoteAddr = "192.0.2.50:1234"
			mux.ServeHTTP(httptest.NewRecorder(), req)
		}
	}

	// 2 per pattern, 2 patterns — and /widgets/a and /widgets/b share one
	// counter because they are the same route.
	if calls != 4 {
		t.Errorf("expected 2 allowed per registered pattern (4 total), got %d", calls)
	}
}

// TestRateLimitWithPattern_SeparatesRoutesOnPatternlessRouters covers the
// case r.Pattern can't: a router that doesn't populate it (chi, gorilla,
// echo) leaves every unlisted route sharing one fallback counter, and
// declaring the pattern is how a consumer gets per-route granularity back.
func TestRateLimitWithPattern_SeparatesRoutesOnPatternlessRouters(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 2, Window: time.Minute},
	}

	var calls int
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	})
	widgets := RateLimitWithPattern(cfg, "GET /widgets/{id}")(handler)
	gadgets := RateLimitWithPattern(cfg, "GET /gadgets/{id}")(handler)

	for i := 0; i < 4; i++ {
		for _, h := range []http.Handler{widgets, gadgets} {
			req := httptest.NewRequest("GET", "/irrelevant/"+fmt.Sprint(i), nil)
			req.RemoteAddr = "192.0.2.50:1234"
			h.ServeHTTP(httptest.NewRecorder(), req)
		}
	}

	if calls != 4 {
		t.Errorf("expected 2 allowed per declared pattern (4 total), got %d", calls)
	}
}

// TestRateLimit_RetryAfterIsAtLeastOne pins the clamp. The header used to be
// int(time.Until(resetAt).Seconds()), which truncates toward zero — any
// window with under a second left emitted "Retry-After: 0", an instruction
// to retry immediately, straight back into the limit.
func TestRateLimit_RetryAfterIsAtLeastOne(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Default:    ratelimit.Rate{Requests: 1, Window: 50 * time.Millisecond},
	}
	rl := RateLimit(cfg)
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	var last *httptest.ResponseRecorder
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/x", nil)
		req.RemoteAddr = "192.0.2.50:1234"
		last = httptest.NewRecorder()
		h.ServeHTTP(last, req)
	}

	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", last.Code)
	}
	if got := last.Header().Get("Retry-After"); got != "1" {
		t.Errorf("expected Retry-After to clamp to 1 on a sub-second window, got %q", got)
	}
}

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
