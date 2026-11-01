package goauth

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func TestProtectMutationSecurityAndParameters(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithRateLimitRoute("POST /widgets/{id}", ratelimit.Rate{Requests: 3, Window: time.Minute}))
	called := 0
	h := f.a.Protect("POST /widgets/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if middleware.GetUserFromContext(r.Context()) == nil {
			t.Error("missing authenticated user")
		}
		if r.PathValue("id") == "" || r.Pattern != "POST /widgets/{id}" {
			t.Error("missing canonical routing context")
		}
		w.WriteHeader(204)
	}))
	f.mux.Handle("POST /widgets/{id}", h)
	// CORS preflight must not authenticate or spend the mutation's budget.
	r := httptest.NewRequest("OPTIONS", "/widgets/1", nil)
	r.Header.Set("Origin", "http://localhost")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "http://localhost" || w.Header().Get("X-RateLimit-Limit") != "" {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}
	// Invalid origin and missing double-submit proof both stop before business code.
	r = httptest.NewRequest("POST", "/widgets/1", nil)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("origin: %d", w.Code)
	}
	r = httptest.NewRequest("POST", "/widgets/1", nil)
	r.Header.Set("Origin", "http://localhost")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF: %d", w.Code)
	}
	f.request(t, "POST", "/widgets/1", "", f.token, 204)
	f.request(t, "POST", "/widgets/2", "", f.token, 429)
	if called != 1 {
		t.Fatalf("business handler called %d times", called)
	}
}

func TestProtectLiveVerificationExpiryAndAuthorization(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithRegistration(RegistrationConfig{RequireEmailVerification: true}))
	h := f.a.Protect("GET /widgets/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, html.EscapeString(r.PathValue("id")))
	}))
	f.mux.Handle("GET /widgets/{id}", h)
	f.mux.Handle("GET /private-admin", f.a.Protect("GET /private-admin", f.a.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))))
	f.request(t, "GET", "/widgets/one", "", "", 401)
	id := uuid.NewString()
	now := time.Now().UTC()
	if err := f.users.Create(t.Context(), &domain.User{ID: id, Email: id + "@example.test", Role: domain.RoleUser, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	session, err := f.a.Services().Session.Create(t.Context(), api.CreateSessionInput{UserID: id})
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/widgets/one", "", session.SessionToken, 403)
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET is_verified=true WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if got := f.request(t, "GET", "/widgets/one", "", session.SessionToken, 200).Body.String(); got != "one" {
		t.Fatalf("path value: %q", got)
	}
	f.request(t, "GET", "/private-admin", "", session.SessionToken, 403)
	// A patternless transport still receives PathValue from the inner ServeMux.
	r := httptest.NewRequest("GET", "/widgets/direct", nil)
	r.Header.Set("Cookie", f.a.cookies.Name+"="+session.SessionToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "direct" {
		t.Fatalf("direct transport: %d %s", w.Code, w.Body.String())
	}
	if _, err := f.db.ExecContext(t.Context(), "UPDATE sessions SET expires_at=$1,refresh_expires_at=$2 WHERE id=$3", now.Add(-time.Hour), now.Add(-time.Hour), session.Session.ID); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/widgets/one", "", session.SessionToken, 401)
}

func TestProtectRejectsInvalidSetup(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	for _, pattern := range []string{"", "POST /widgets/*", "POST /widgets/{id"} {
		t.Run(pattern, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid pattern accepted")
				}
			}()
			f.a.Protect(pattern, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		})
	}
	defer func() {
		if recover() == nil {
			t.Fatal("nil handler accepted")
		}
	}()
	f.a.Protect("GET /nil", nil)
}

func TestProtectRejectsMismatchedRoute(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	h := f.a.Protect("GET /widgets/{id}", http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { t.Fatal("mismatch reached business code") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/other/one", strings.NewReader("")))
	if w.Code != 404 {
		t.Fatalf("mismatch: %d", w.Code)
	}
}
