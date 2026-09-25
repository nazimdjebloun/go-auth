package goauth

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/internal/httproutes"
	"github.com/nazimdjebloun/go-auth/internal/routes"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func TestHandlerRegistryRespectsFeatureGates(t *testing.T) {
	a := buildAuth(t, minimalOpts()...)
	defer a.Close()

	if len(a.routes) != 52 {
		t.Fatalf("default route count = %d, want 52", len(a.routes))
	}
	for _, pattern := range []string{routes.Login, routes.Register, routes.Me} {
		if h, ok := a.Handler(pattern); !ok || h == nil {
			t.Errorf("enabled route %q is unavailable", pattern)
		}
	}
	for _, pattern := range []string{routes.InviteInfo, routes.OAuthInitiate, routes.CreateOrg, "GET /unknown"} {
		if h, ok := a.Handler(pattern); ok || h != nil {
			t.Errorf("disabled or unknown route %q is available", pattern)
		}
	}
}

func TestServicesPreservesDisabledCapabilities(t *testing.T) {
	a := buildAuth(t, minimalOpts()...)
	defer a.Close()

	services := a.Services()
	if services.OAuth != nil || services.Org != nil || services.OrgInvite != nil {
		t.Fatalf("disabled capabilities must be nil: OAuth=%v Org=%v OrgInvite=%v", services.OAuth, services.Org, services.OrgInvite)
	}
	if services.Auth == nil || services.Session == nil {
		t.Fatal("enabled capabilities are nil")
	}
	services.Auth = nil
	if a.Services().Auth == nil {
		t.Fatal("mutating the returned Services value changed Auth wiring")
	}
}

func TestHandlerSetsPatternForCustomRouter(t *testing.T) {
	const pattern = "GET /widgets/{id}"
	var gotPattern, gotID string
	a := &Auth{routes: []httproutes.Entry{{Pattern: pattern, Handler: http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotPattern = r.Pattern
		gotID = r.PathValue("id")
	})}}}
	h, ok := a.Handler(pattern)
	if !ok {
		t.Fatal("handler lookup failed")
	}
	req := httptest.NewRequest(http.MethodGet, "/widgets/42", nil)
	req.SetPathValue("id", "42")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if gotPattern != pattern || gotID != "42" {
		t.Fatalf("handler saw pattern %q and id %q", gotPattern, gotID)
	}
	if req.Pattern != "" {
		t.Fatalf("handler changed caller request pattern to %q", req.Pattern)
	}
}

// TestClose_DoesNotCloseConsumerSuppliedPool guards the DatabaseConfig.Pool
// contract ("library borrows, does not close"): Close() must only close a
// pool it opened itself, never one handed in by the consumer.
func TestClose_DoesNotCloseConsumerSuppliedPool(t *testing.T) {
	// Lazy: pgxpool.New does not dial until first use, so this succeeds
	// without a reachable Postgres server.
	pool, err := pgxpool.New(context.Background(), "postgres://user:pass@127.0.0.1:1/db")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	defer pool.Close()

	cfg, err := NewConfig(append(minimalOpts(), WithApp(AppConfig{
		Name:     "app",
		BaseURL:  "https://example.com",
		Database: DatabaseConfig{Driver: DriverPostgres, Pool: pool},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	a.Close()

	// Acquire from a closed pgxpool.Pool fails immediately with "closed
	// pool" — no dial attempt. Acquire from an open-but-unreachable pool
	// instead blocks trying to dial 127.0.0.1:1 until ctx expires. Either
	// outcome other than "closed pool" proves Close() left this pool open.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, acquireErr := pool.Acquire(ctx); acquireErr != nil && acquireErr.Error() == "closed pool" {
		t.Fatal("Close() closed a consumer-supplied Pool — DatabaseConfig.Pool is documented as library borrows, does not close")
	}
}

// TestSetSessionCookies verifies the custom-handler cookie-writing path
// (a.Services().Auth.Login + a.SetSessionCookies) produces cookies with the
// configured name/Secure/SameSite/Path, and that an empty refresh token is
// omitted rather than written as an empty cookie.
func TestSetSessionCookies(t *testing.T) {
	a := buildAuth(t, minimalOpts()...)
	defer a.Close()

	w := httptest.NewRecorder()
	a.SetSessionCookies(w, "session-token-value", "refresh-token-value")

	cookies := w.Result().Cookies()
	var session, refresh *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case "goauth_session":
			session = c
		case "goauth_refresh":
			refresh = c
		}
	}
	if session == nil {
		t.Fatal("session cookie not set")
	}
	if session.Value != "session-token-value" {
		t.Errorf("session cookie value = %q, want %q", session.Value, "session-token-value")
	}
	if !session.Secure || !session.HttpOnly || session.Path != "/" || session.SameSite != http.SameSiteLaxMode {
		t.Errorf("session cookie attrs = %+v, want Secure/HttpOnly/Path=/ /SameSite=Lax", session)
	}
	if refresh == nil {
		t.Fatal("refresh cookie not set")
	}
	if refresh.Value != "refresh-token-value" {
		t.Errorf("refresh cookie value = %q, want %q", refresh.Value, "refresh-token-value")
	}

	w2 := httptest.NewRecorder()
	a.SetSessionCookies(w2, "session-token-value", "")
	for _, c := range w2.Result().Cookies() {
		if c.Name == "goauth_refresh" {
			t.Fatal("empty refresh token must not produce a refresh cookie")
		}
	}
}

// TestRegister_PersistsIPAndUserAgent guards the programmatic registration
// path's propagation of client metadata into the issued session.
func TestRegister_PersistsIPAndUserAgent(t *testing.T) {
	a := buildAuth(t, minimalOpts()...)
	defer a.Close()

	res, aerr := a.Register(context.Background(), api.RegisterInput{
		Email:     "ada@example.com",
		Password:  validTestPassword(),
		Name:      "Ada",
		IP:        "203.0.113.7",
		UserAgent: "test-agent/1.0",
	})
	if aerr != nil {
		t.Fatalf("Register: %v", aerr)
	}
	if res.Session == nil {
		t.Fatal("expected a session on the normal Register success path")
	}
	if res.Session.IP != "203.0.113.7" {
		t.Errorf("session.IP = %q, want %q", res.Session.IP, "203.0.113.7")
	}
	if res.Session.UserAgent != "test-agent/1.0" {
		t.Errorf("session.UserAgent = %q, want %q", res.Session.UserAgent, "test-agent/1.0")
	}
}

// TestLogin_PersistsIPAndUserAgent is the Login counterpart — api.LoginInput
// already carried IP/UserAgent before the aliasing change, so this locks in
// behavior that already worked rather than guarding a regression.
func TestLogin_PersistsIPAndUserAgent(t *testing.T) {
	a := buildAuth(t, minimalOpts()...)
	defer a.Close()

	if _, aerr := a.Register(context.Background(), api.RegisterInput{
		Email:    "bob@example.com",
		Password: validTestPassword(),
		Name:     "Bob",
	}); aerr != nil {
		t.Fatalf("Register: %v", aerr)
	}

	res, aerr := a.Login(context.Background(), api.LoginInput{
		Email:     "bob@example.com",
		Password:  validTestPassword(),
		IP:        "198.51.100.9",
		UserAgent: "test-agent/2.0",
	})
	if aerr != nil {
		t.Fatalf("Login: %v", aerr)
	}
	if res.Session == nil {
		t.Fatal("expected a session on the normal Login success path")
	}
	if res.Session.IP != "198.51.100.9" {
		t.Errorf("session.IP = %q, want %q", res.Session.IP, "198.51.100.9")
	}
	if res.Session.UserAgent != "test-agent/2.0" {
		t.Errorf("session.UserAgent = %q, want %q", res.Session.UserAgent, "test-agent/2.0")
	}
}

// fakeRateLimitStore is a Store implementation distinct from
// ratelimit.NewMemoryStore's, used to prove the default-store warning is
// type-based rather than firing unconditionally whenever rate limiting is on.
type fakeRateLimitStore struct{}

func (fakeRateLimitStore) Allow(_ context.Context, _ string, _ ratelimit.Rate) (ratelimit.Result, error) {
	return ratelimit.Result{Allowed: true}, nil
}

type denyRateLimitStore struct{}

func (denyRateLimitStore) Allow(_ context.Context, _ string, _ ratelimit.Rate) (ratelimit.Result, error) {
	return ratelimit.Result{Allowed: false, ResetAt: time.Now().Add(time.Minute)}, nil
}

func TestPasswordConfirmationRoutesAreRateLimited(t *testing.T) {
	a := buildAuth(t, minimalOpts(WithRateLimitStore(denyRateLimitStore{}))...)
	defer a.Close()

	tests := []struct {
		name   string
		path   string
		method string
	}{
		{name: "change password", path: "/auth/change-password", method: http.MethodPost},
		{name: "delete account", path: "/auth/account", method: http.MethodDelete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, ok := a.Handler(tt.method + " " + tt.path)
			if !ok {
				t.Fatal("enabled handler is missing")
			}
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("status = %d, want %d", w.Code, http.StatusTooManyRequests)
			}
		})
	}
}

func TestNew_WarnsWhenRateLimitUsesDefaultStore(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// minimalOpts doesn't touch rate limiting, so New() falls back to
	// ratelimit.DefaultRateLimitConfig() — Enabled: true, Store:
	// NewMemoryStore() — which is exactly the case the warning targets.
	buildAuth(t, minimalOpts(WithLogger(logger))...)

	if !strings.Contains(buf.String(), "does not share state across instances") {
		t.Errorf("expected a warning about the default in-memory rate-limit store, got log:\n%s", buf.String())
	}
}

func TestNew_NoWarningWithCustomRateLimitStore(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	buildAuth(t, minimalOpts(WithLogger(logger), WithRateLimitStore(fakeRateLimitStore{}))...)

	if strings.Contains(buf.String(), "does not share state across instances") {
		t.Errorf("expected no default-store warning with a custom Store, got log:\n%s", buf.String())
	}
}

func TestNew_NoWarningWhenRateLimitDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	buildAuth(t, minimalOpts(WithLogger(logger), WithRateLimitEnabled(false))...)

	if strings.Contains(buf.String(), "does not share state across instances") {
		t.Errorf("expected no default-store warning when rate limiting is disabled, got log:\n%s", buf.String())
	}
}

// closeTrackingStore is a Store + StoreCloser that records whether Close was
// called, used to prove Auth.Close() never touches a consumer-supplied
// Store — per WithRateLimitStore's contract, that Store is a live object
// the consumer owns.
type closeTrackingStore struct {
	closed *bool
}

func (closeTrackingStore) Allow(_ context.Context, _ string, _ ratelimit.Rate) (ratelimit.Result, error) {
	return ratelimit.Result{Allowed: true}, nil
}
func (s closeTrackingStore) Close() { *s.closed = true }

func TestClose_DoesNotCloseConsumerSuppliedRateLimitStore(t *testing.T) {
	closed := false
	store := closeTrackingStore{closed: &closed}

	a := buildAuth(t, minimalOpts(WithRateLimitStore(store))...)
	a.Close()

	if closed {
		t.Error("Close() closed a consumer-supplied rate-limit Store — WithRateLimitStore's contract is that the consumer owns it")
	}
}

// TestClose_ClosesDefaultRateLimitStore proves Auth.Close() stops the
// default store's cleanup goroutine when nothing overrode it. Goroutine
// counting is inherently a little noisy, so this polls for a shrink rather
// than asserting an exact count immediately after Close.
func TestClose_ClosesDefaultRateLimitStore(t *testing.T) {
	a := buildAuth(t, minimalOpts()...) // no WithRateLimitStore/WithRateLimit — default path

	before := runtime.NumGoroutine()
	a.Close()

	deadline := time.Now().Add(2 * time.Second)
	for {
		after := runtime.NumGoroutine()
		if after < before {
			return // cleanup goroutine (and possibly others) exited
		}
		if time.Now().After(deadline) {
			t.Fatalf("goroutine count did not shrink after Close(): before=%d after=%d", before, after)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
