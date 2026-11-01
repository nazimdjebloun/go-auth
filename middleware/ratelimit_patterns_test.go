package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func TestRateLimitCanonicalPatternsAndExemptions(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled: true, Default: ratelimit.Rate{Requests: 20, Window: time.Minute},
		Routes: map[string]ratelimit.Rate{
			"POST /widgets/{id}":   {Requests: 1, Window: time.Minute},
			"GET /files/{rest...}": {Requests: 1, Window: time.Minute},
		},
		DisabledRoutes: []string{"GET /widgets/{id}"},
	}
	t.Cleanup(func() {
		if closer, ok := cfg.Store.(ratelimit.StoreCloser); ok {
			closer.Close()
		}
	})
	h := RateLimit(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		method, path string
		status       int
		counted      bool
	}{
		{"GET", "/widgets/1", 204, false}, {"GET", "/widgets/2", 204, false},
		{"POST", "/widgets/1", 204, true}, {"POST", "/widgets/2", 429, true},
		{"GET", "/files/a/b", 204, true}, {"GET", "/files/c/d", 429, true},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tc.method, tc.path, nil)
		h.ServeHTTP(w, r)
		if w.Code != tc.status || (w.Header().Get("X-RateLimit-Limit") != "") != tc.counted {
			t.Errorf("%s %s: status=%d headers=%v", tc.method, tc.path, w.Code, w.Header())
		}
	}
}

func TestRateLimitDeclaredPatternRejectsMismatchBeforeCounting(t *testing.T) {
	cfg := &ratelimit.Config{Enabled: true, Default: ratelimit.Rate{Requests: 1, Window: time.Minute}}
	h := RateLimitWithPattern(cfg, "POST /widgets/{id}")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	t.Cleanup(func() {
		if closer, ok := cfg.Store.(ratelimit.StoreCloser); ok {
			closer.Close()
		}
	})
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/elsewhere/a", 404}, {"/widgets/a", 204}, {"/widgets/b", 429},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", tc.path, nil))
		if w.Code != tc.status {
			t.Errorf("%s: got %d want %d", tc.path, w.Code, tc.status)
		}
	}
}

func TestRateLimitInvalidDeclarationPanicsEvenWhenDisabled(t *testing.T) {
	for _, pattern := range []string{"", "POST /widgets/*", "POST /widgets/{id"} {
		t.Run(pattern, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid declaration accepted")
				}
			}()
			RateLimitWithPattern(nil, pattern)
		})
	}
}
