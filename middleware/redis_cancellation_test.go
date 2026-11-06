package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func TestRateLimitCanceledRequestStopsBeforeHandler(t *testing.T) {
	store := ratelimit.NewMemoryStore()
	defer store.(ratelimit.StoreCloser).Close()
	cfg := &ratelimit.Config{Enabled: true, Default: ratelimit.Rate{Requests: 10, Window: time.Minute}, Store: store}
	called := false
	handler := RateLimit(cfg)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://example.test/", nil).WithContext(ctx))
	if called {
		t.Fatal("canceled request reached handler")
	}
}
