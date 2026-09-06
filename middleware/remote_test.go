package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// ── helpers ─────────────────────────────────────────────────────────────

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// upstream spins up a stand-in go-auth server exposing GET /auth/me, and
// counts how many times it was called so tests can assert every request asks.
type upstream struct {
	*httptest.Server
	calls   atomic.Int64
	cookies []string // sent back as Set-Cookie on every response
}

func newUpstream(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *upstream {
	t.Helper()
	up := &upstream{}
	up.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		up.calls.Add(1)
		for _, c := range up.cookies {
			w.Header().Add("Set-Cookie", c)
		}
		handler(w, r)
	}))
	t.Cleanup(up.Close)
	return up
}

// okUser replies the way GET /auth/me does — domain.User embedded at the top
// level alongside hasPassword.
func okUser(user domain.User) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			domain.User
			HasPassword bool `json:"hasPassword"`
		}{user, true})
	}
}

func status(code int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }
}

func adminUser() domain.User {
	return domain.User{ID: "u-1", Email: "admin@example.com", Name: "Admin", Role: domain.RoleAdmin}
}

func normalUser() domain.User {
	return domain.User{ID: "u-2", Email: "user@example.com", Name: "User", Role: domain.RoleUser}
}

func newRemote(t *testing.T, base string, opts ...RemoteOption) *RemoteAuth {
	t.Helper()
	ra, err := NewRemoteAuth(base, append([]RemoteOption{WithRemoteLogger(quietLogger())}, opts...)...)
	if err != nil {
		t.Fatalf("NewRemoteAuth: %v", err)
	}
	return ra
}

func withSession(r *http.Request, value string) *http.Request {
	r.AddCookie(&http.Cookie{Name: "goauth_session", Value: value})
	return r
}

// remoteNext records that it ran and which user reached it.
func remoteNext(seen **domain.User) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = GetUserFromContext(r.Context())
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("reached"))
	})
}

func decodeErrEnvelope(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not the {error,message} envelope: %v (%q)", err, rec.Body.String())
	}
	return body
}

// ── constructor ─────────────────────────────────────────────────────────

func TestNewRemoteAuth_ValidURLs(t *testing.T) {
	for _, in := range []struct{ url, want string }{
		{"https://api.example.com", "https://api.example.com"},
		{"http://localhost:8080", "http://localhost:8080"},
		{"https://api.example.com/", "https://api.example.com"},
		{"https://api.example.com///", "https://api.example.com"},
		{"  https://api.example.com  ", "https://api.example.com"},
		{"https://api.example.com/base", "https://api.example.com/base"},
	} {
		ra, err := NewRemoteAuth(in.url)
		if err != nil {
			t.Fatalf("NewRemoteAuth(%q): unexpected error %v", in.url, err)
		}
		if ra.baseURL != in.want {
			t.Errorf("NewRemoteAuth(%q): baseURL = %q, want %q", in.url, ra.baseURL, in.want)
		}
	}
}

func TestNewRemoteAuth_RejectsBadURLs(t *testing.T) {
	for _, in := range []string{"", "   ", "/", "ftp://example.com", "file:///etc/passwd", "example.com", "://nope", "http://"} {
		if _, err := NewRemoteAuth(in); err == nil {
			t.Errorf("NewRemoteAuth(%q): expected an error, got nil", in)
		}
	}
}

func TestNewRemoteAuth_Defaults(t *testing.T) {
	ra, err := NewRemoteAuth("https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ra.cookieName != "goauth_session" {
		t.Errorf("cookieName = %q, want goauth_session", ra.cookieName)
	}
	if ra.client.Timeout != defaultRemoteTimeout {
		t.Errorf("client timeout = %v, want %v", ra.client.Timeout, defaultRemoteTimeout)
	}
	if ra.client.CheckRedirect == nil {
		t.Error("CheckRedirect must be set so redirects are never followed")
	}
	if ra.logger == nil {
		t.Error("logger should default to slog.Default(), got nil")
	}
}

func TestNewRemoteAuth_OptionsApplied(t *testing.T) {
	ra := newRemote(t, "https://api.example.com", WithRemoteCookieName("custom_session"))
	if ra.cookieName != "custom_session" {
		t.Errorf("cookieName = %q, want custom_session", ra.cookieName)
	}
}

// A nil or zero-valued option must not clobber a good default — otherwise a
// caller passing an optional value through would silently disable a safeguard.
func TestNewRemoteAuth_OptionsIgnoreZeroValues(t *testing.T) {
	ra := newRemote(t, "https://api.example.com",
		WithRemoteHTTPClient(nil),
		WithRemoteCookieName(""),
		WithRemoteLogger(nil),
	)
	if ra.client == nil || ra.client.Timeout != defaultRemoteTimeout {
		t.Error("nil client option should have left the default client in place")
	}
	if ra.cookieName != "goauth_session" {
		t.Errorf("cookieName = %q, want the default to survive", ra.cookieName)
	}
	if ra.logger == nil {
		t.Error("nil logger option should have left a logger in place")
	}
}

// A caller's http.Client must not be mutated by us — they may share it.
func TestNewRemoteAuth_DoesNotMutateCallersClient(t *testing.T) {
	caller := &http.Client{}
	ra := newRemote(t, "https://api.example.com", WithRemoteHTTPClient(caller))
	if caller.Timeout != 0 {
		t.Errorf("caller's client was mutated: timeout = %v, want 0", caller.Timeout)
	}
	if caller.CheckRedirect != nil {
		t.Error("caller's client CheckRedirect was mutated")
	}
	if ra.client.Timeout != defaultRemoteTimeout {
		t.Errorf("internal client timeout = %v, want the default applied", ra.client.Timeout)
	}
}

func TestNewRemoteAuth_KeepsCallersTimeout(t *testing.T) {
	ra := newRemote(t, "https://api.example.com",
		WithRemoteHTTPClient(&http.Client{Timeout: 3 * time.Second}))
	if ra.client.Timeout != 3*time.Second {
		t.Errorf("client timeout = %v, want 3s", ra.client.Timeout)
	}
}

// Redirect suppression is not negotiable: a caller cannot re-enable it by
// supplying a client with its own CheckRedirect.
func TestNewRemoteAuth_OverridesCallersCheckRedirect(t *testing.T) {
	followed := false
	caller := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		followed = true
		return nil
	}}
	ra := newRemote(t, "https://api.example.com", WithRemoteHTTPClient(caller))

	err := ra.client.CheckRedirect(nil, nil)
	if !errors.Is(err, http.ErrUseLastResponse) {
		t.Errorf("CheckRedirect returned %v, want http.ErrUseLastResponse", err)
	}
	if followed {
		t.Error("the caller's permissive CheckRedirect was used")
	}
}

// ── redirects (regression: session cookie leak) ─────────────────────────

// Go copies the Cookie header across a redirect when only the port differs —
// it compares hostnames and ignores ports. Following a 3xx would therefore
// hand a live session cookie to any co-located service, so redirects must not
// be followed at all.
func TestRemote_DoesNotFollowRedirects(t *testing.T) {
	var victimSaw string
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		victimSaw = r.Header.Get("Cookie")
		okUser(adminUser())(w, r)
	}))
	t.Cleanup(victim.Close)

	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, victim.URL+"/steal", http.StatusFound)
	})
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec,
		withSession(httptest.NewRequest("GET", "/x", nil), "SECRET"))

	if strings.Contains(victimSaw, "SECRET") {
		t.Fatalf("session cookie leaked to the redirect target: %q", victimSaw)
	}
	if victimSaw != "" {
		t.Fatalf("redirect target was contacted at all: %q", victimSaw)
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (a redirect leaves auth undecided)", rec.Code)
	}
}

func TestRemote_RedirectStatusesAreUnavailable(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "http://example.invalid/steal")
			w.WriteHeader(code)
		})
		ra := newRemote(t, up.URL)

		_, err := ra.GetUser(t.Context(), "goauth_session=tok")
		if !errors.Is(err, ErrRemoteUnavailable) {
			t.Errorf("upstream %d: error = %v, want ErrRemoteUnavailable", code, err)
		}
	}
}

// ── no caching (regression: stale authorization) ────────────────────────

// AuthMiddleware re-reads the session and user from the database per request;
// RemoteAuth must match that or a revoked session keeps working.
func TestRemote_AsksUpstreamEveryRequest(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	for i := 0; i < 5; i++ {
		ra.RequireAuth(remoteNext(nil)).ServeHTTP(httptest.NewRecorder(),
			withSession(httptest.NewRequest("GET", "/x", nil), "tok"))
	}
	if got := up.calls.Load(); got != 5 {
		t.Errorf("upstream calls = %d, want 5 — the check must never be skipped", got)
	}
}

// A demotion takes effect on the next request. UpdateUserRole does not revoke
// sessions, so nothing else would ever catch it.
func TestRemote_DemotionTakesEffectImmediately(t *testing.T) {
	var demoted atomic.Bool
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if demoted.Load() {
			okUser(normalUser())(w, r)
			return
		}
		okUser(adminUser())(w, r)
	})
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAdmin(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))
	if rec.Code != http.StatusOK {
		t.Fatalf("before demotion: status = %d, want 200", rec.Code)
	}

	demoted.Store(true)

	rec = httptest.NewRecorder()
	ra.RequireAdmin(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("after demotion: status = %d, want 403 on the very next request", rec.Code)
	}
}

// A revoked session must stop working on the next request, not eventually.
func TestRemote_RevocationTakesEffectImmediately(t *testing.T) {
	var revoked atomic.Bool
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if revoked.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		okUser(adminUser())(w, r)
	})
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))
	if rec.Code != http.StatusOK {
		t.Fatalf("before revocation: status = %d, want 200", rec.Code)
	}

	revoked.Store(true)

	rec = httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("after revocation: status = %d, want 401 on the very next request", rec.Code)
	}
}

// Regression: every request must get its own *domain.User. Sharing one across
// requests let a handler's mutation leak into unrelated requests.
func TestRemote_EachRequestGetsItsOwnUser(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	var first, second *domain.User

	ra.RequireAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		first = GetUserFromContext(r.Context())
		first.Role = domain.RoleUser
		first.Email = "tampered@evil.test"
	})).ServeHTTP(httptest.NewRecorder(), withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	ra.RequireAuth(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		second = GetUserFromContext(r.Context())
	})).ServeHTTP(httptest.NewRecorder(), withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if first == second {
		t.Fatal("both requests received the same *domain.User pointer")
	}
	if second.Email != "admin@example.com" || second.Role != domain.RoleAdmin {
		t.Errorf("request 2 saw role=%q email=%q — request 1's mutation leaked",
			second.Role, second.Email)
	}
}

// ── RequireAuth ─────────────────────────────────────────────────────────

func TestRemoteRequireAuth_ValidSessionReachesHandler(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	var seen *domain.User
	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(&seen)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
	if seen == nil {
		t.Fatal("handler saw no user in context")
	}
	if seen.ID != "u-1" || seen.Email != "admin@example.com" || seen.Role != domain.RoleAdmin {
		t.Errorf("context user = %+v, want the upstream admin", seen)
	}
}

// No cookie must short-circuit without troubling the upstream server — an
// unauthenticated flood should not become an upstream flood.
func TestRemoteRequireAuth_NoCookieDoesNotCallUpstream(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, httptest.NewRequest("GET", "/x", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := up.calls.Load(); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}
	if body := decodeErrEnvelope(t, rec); body["error"] != "session_expired" {
		t.Errorf("error code = %q, want session_expired", body["error"])
	}
}

func TestRemoteRequireAuth_WrongCookieNameIsNoSession(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	r := httptest.NewRequest("GET", "/x", nil)
	r.AddCookie(&http.Cookie{Name: "some_other_cookie", Value: "tok"})
	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := up.calls.Load(); got != 0 {
		t.Errorf("upstream calls = %d, want 0", got)
	}
}

func TestRemoteRequireAuth_CustomCookieName(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL, WithRemoteCookieName("custom_session"))

	r := httptest.NewRequest("GET", "/x", nil)
	r.AddCookie(&http.Cookie{Name: "custom_session", Value: "tok"})
	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRemoteRequireAuth_UpstreamRejectionsAre401(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		up := newUpstream(t, status(code))
		ra := newRemote(t, up.URL)

		rec := httptest.NewRecorder()
		ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("upstream %d: status = %d, want 401", code, rec.Code)
		}
		if body := decodeErrEnvelope(t, rec); body["error"] != "unauthorized" {
			t.Errorf("upstream %d: error code = %q, want unauthorized", code, body["error"])
		}
	}
}

// An upstream that is broken rather than answering "no" must fail closed, but
// as 503 — reporting 401 would tell a signed-in admin they were logged out.
func TestRemoteRequireAuth_UpstreamFailureIs503(t *testing.T) {
	for _, code := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusNotFound, http.StatusTooManyRequests} {
		up := newUpstream(t, status(code))
		ra := newRemote(t, up.URL)

		rec := httptest.NewRecorder()
		ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("upstream %d: status = %d, want 503", code, rec.Code)
		}
		if body := decodeErrEnvelope(t, rec); body["error"] != "auth_unavailable" {
			t.Errorf("upstream %d: error code = %q, want auth_unavailable", code, body["error"])
		}
	}
}

func TestRemoteRequireAuth_UnreachableUpstreamIs503(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	base := up.URL
	up.Close() // nothing is listening now

	ra := newRemote(t, base)
	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestRemoteRequireAuth_MalformedUpstreamBodyIs503(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is not json"))
	})
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// A 200 carrying an empty user is a contract violation, not an anonymous
// caller — admitting it would put a zero-valued domain.User in the context.
func TestRemoteRequireAuth_EmptyUserIDIs503(t *testing.T) {
	up := newUpstream(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"email":"nobody@example.com"}`))
	})
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestRemoteRequireAuth_ForwardsCookieHeaderAndPath(t *testing.T) {
	var gotCookie, gotPath, gotAccept string
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
		gotPath = r.URL.Path
		gotAccept = r.Header.Get("Accept")
		okUser(adminUser())(w, r)
	})
	ra := newRemote(t, up.URL)

	r := httptest.NewRequest("GET", "/x", nil)
	r.AddCookie(&http.Cookie{Name: "goauth_session", Value: "sess-abc"})
	r.AddCookie(&http.Cookie{Name: "goauth_refresh", Value: "refresh-xyz"})
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(httptest.NewRecorder(), r)

	if !strings.Contains(gotCookie, "goauth_session=sess-abc") {
		t.Errorf("session cookie not forwarded: %q", gotCookie)
	}
	// The refresh cookie has to travel too, or upstream can never perform the
	// transparent refresh that keeps a long session alive.
	if !strings.Contains(gotCookie, "goauth_refresh=refresh-xyz") {
		t.Errorf("refresh cookie not forwarded: %q", gotCookie)
	}
	if gotPath != "/auth/me" {
		t.Errorf("upstream path = %q, want /auth/me", gotPath)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
}

func TestRemoteRequireAuth_HonoursBaseURLSubpath(t *testing.T) {
	var gotPath string
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		okUser(adminUser())(w, r)
	})
	ra := newRemote(t, up.URL+"/api")

	ra.RequireAuth(remoteNext(nil)).ServeHTTP(httptest.NewRecorder(),
		withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if gotPath != "/api/auth/me" {
		t.Errorf("upstream path = %q, want /api/auth/me", gotPath)
	}
}

func TestRemoteRequireAuth_ErrorResponsesAreJSON(t *testing.T) {
	up := newUpstream(t, status(http.StatusUnauthorized))
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := decodeErrEnvelope(t, rec)
	if body["error"] == "" || body["message"] == "" {
		t.Errorf("envelope missing error/message: %#v", body)
	}
}

// The rejected request must never reach the wrapped handler.
func TestRemoteRequireAuth_HandlerNotCalledOnRejection(t *testing.T) {
	up := newUpstream(t, status(http.StatusUnauthorized))
	ra := newRemote(t, up.URL)

	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	ra.RequireAuth(next).ServeHTTP(httptest.NewRecorder(),
		withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if called {
		t.Error("wrapped handler ran despite a rejected session")
	}
}

// ── RequireAdmin / RequireRole ──────────────────────────────────────────

func TestRemoteRequireAdmin_AllowsAdmin(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAdmin(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}
}

// Reusing RequireRole means a remotely-authenticated 403 is byte-identical to
// a locally-authenticated one, so clients cannot tell the two apart.
func TestRemoteRequireAdmin_RejectsNonAdminWith403(t *testing.T) {
	up := newUpstream(t, okUser(normalUser()))
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAdmin(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	body := decodeErrEnvelope(t, rec)
	if body["error"] != "forbidden" {
		t.Errorf("error code = %q, want forbidden", body["error"])
	}
	if body["message"] != "Insufficient permissions" {
		t.Errorf("message = %q, want the same text RequireRole uses", body["message"])
	}
}

func TestRemoteRequireRole_MatchesAndRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		user domain.User
		role domain.Role
		want int
	}{
		{"user route, user", normalUser(), domain.RoleUser, http.StatusOK},
		{"user route, admin", adminUser(), domain.RoleUser, http.StatusForbidden},
		{"admin route, admin", adminUser(), domain.RoleAdmin, http.StatusOK},
		{"admin route, user", normalUser(), domain.RoleAdmin, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := newUpstream(t, okUser(tc.user))
			ra := newRemote(t, up.URL)

			rec := httptest.NewRecorder()
			ra.RequireRole(tc.role)(remoteNext(nil)).ServeHTTP(rec,
				withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d", rec.Code, tc.want)
			}
		})
	}
}

// A request costs exactly one upstream call, not one per middleware layer.
func TestRemoteRequireAdmin_OneUpstreamCallPerRequest(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	ra.RequireAdmin(remoteNext(nil)).ServeHTTP(httptest.NewRecorder(),
		withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if got := up.calls.Load(); got != 1 {
		t.Errorf("upstream calls = %d, want 1", got)
	}
}

// ── Set-Cookie forwarding ───────────────────────────────────────────────

// If upstream transparently refreshes the session, dropping its Set-Cookie
// would leave the browser holding a rotated refresh token — which the next
// refresh reads as token reuse.
func TestRemote_ForwardsUpstreamSetCookie(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	up.cookies = []string{
		"goauth_session=new-session; Path=/; HttpOnly",
		"goauth_refresh=new-refresh; Path=/; HttpOnly",
	}
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "old"))

	got := rec.Header().Values("Set-Cookie")
	if len(got) != 2 {
		t.Fatalf("forwarded %d Set-Cookie headers, want 2: %v", len(got), got)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "new-session") || !strings.Contains(joined, "new-refresh") {
		t.Errorf("forwarded cookies = %v, want both rotated cookies", got)
	}
}

func TestRemote_NoSetCookieWhenUpstreamSendsNone(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	rec := httptest.NewRecorder()
	ra.RequireAuth(remoteNext(nil)).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), "tok"))

	if got := rec.Header().Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("Set-Cookie = %v, want none", got)
	}
}

// ── GetUser ─────────────────────────────────────────────────────────────

func TestRemoteGetUser_Success(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	user, err := ra.GetUser(t.Context(), "goauth_session=tok")
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if user.ID != "u-1" || user.Role != domain.RoleAdmin {
		t.Errorf("user = %+v, want the upstream admin", user)
	}
}

func TestRemoteGetUser_ErrorsAreDistinguishable(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request)
		cookie  string
		want    error
	}{
		{"no cookie", okUser(adminUser()), "", ErrRemoteNoSession},
		{"other cookie only", okUser(adminUser()), "unrelated=1", ErrRemoteNoSession},
		{"upstream 401", status(http.StatusUnauthorized), "goauth_session=tok", ErrRemoteUnauthorized},
		{"upstream 403", status(http.StatusForbidden), "goauth_session=tok", ErrRemoteUnauthorized},
		{"upstream 500", status(http.StatusInternalServerError), "goauth_session=tok", ErrRemoteUnavailable},
		{"upstream 404", status(http.StatusNotFound), "goauth_session=tok", ErrRemoteUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := newUpstream(t, tc.handler)
			ra := newRemote(t, up.URL)

			_, err := ra.GetUser(t.Context(), tc.cookie)
			if !errors.Is(err, tc.want) {
				t.Errorf("GetUser error = %v, want errors.Is(..., %v)", err, tc.want)
			}
		})
	}
}

// The wrapped errors must keep their sentinel identity through fmt.Errorf.
func TestRemoteGetUser_UnavailableWrapsCause(t *testing.T) {
	up := newUpstream(t, status(http.StatusBadGateway))
	ra := newRemote(t, up.URL)

	_, err := ra.GetUser(t.Context(), "goauth_session=tok")
	if !errors.Is(err, ErrRemoteUnavailable) {
		t.Fatalf("error = %v, want ErrRemoteUnavailable", err)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Errorf("error %q should mention the upstream status", err)
	}
}

// A cancelled request context must abort the upstream call rather than
// blocking on it.
func TestRemoteGetUser_HonoursContextCancellation(t *testing.T) {
	release := make(chan struct{})
	up := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		okUser(adminUser())(w, r)
	})
	t.Cleanup(func() { close(release) })

	ra := newRemote(t, up.URL)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := ra.GetUser(ctx, "goauth_session=tok"); !errors.Is(err, ErrRemoteUnavailable) {
		t.Errorf("error = %v, want ErrRemoteUnavailable on a cancelled context", err)
	}
}

// ── cookie parsing ──────────────────────────────────────────────────────

func TestSessionCookieValue(t *testing.T) {
	for _, tc := range []struct {
		header, name, want string
	}{
		{"goauth_session=abc", "goauth_session", "abc"},
		{"a=1; goauth_session=abc; b=2", "goauth_session", "abc"},
		{"goauth_session=abc", "other", ""},
		{"", "goauth_session", ""},
		{"goauth_session=abc", "", ""},
		{"malformed", "goauth_session", ""},
		{"goauth_session=", "goauth_session", ""},
		{`goauth_session="quoted"`, "goauth_session", "quoted"},
	} {
		if got := sessionCookieValue(tc.header, tc.name); got != tc.want {
			t.Errorf("sessionCookieValue(%q, %q) = %q, want %q", tc.header, tc.name, got, tc.want)
		}
	}
}

// ── concurrency ─────────────────────────────────────────────────────────

// Run with -race: concurrent requests must share no state, including the user
// they put in the context.
func TestRemote_ConcurrentRequests(t *testing.T) {
	up := newUpstream(t, okUser(adminUser()))
	ra := newRemote(t, up.URL)

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := fmt.Sprintf("tok-%d", i%8)
			rec := httptest.NewRecorder()
			ra.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if u := GetUserFromContext(r.Context()); u != nil {
					u.Name = fmt.Sprintf("goroutine-%d", i)
				}
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rec, withSession(httptest.NewRequest("GET", "/x", nil), token))
			if rec.Code != http.StatusOK {
				t.Errorf("goroutine %d: status = %d, want 200", i, rec.Code)
			}
			if _, err := ra.GetUser(t.Context(), "goauth_session="+token); err != nil {
				t.Errorf("goroutine %d: GetUser: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
}
