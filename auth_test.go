package goauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

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
// (a.Services.Auth.Login + a.SetSessionCookies) produces cookies with the
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
