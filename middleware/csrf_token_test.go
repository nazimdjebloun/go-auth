package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
)

const testSecret = "0123456789abcdef0123456789abcdef"

func testCSRFConfig() *CSRFTokenConfig { return &CSRFTokenConfig{Secret: []byte(testSecret)} }
func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
}
func csrfBootstrap(t *testing.T, cfg *CSRFTokenConfig, cookies ...*http.Cookie) (*httptest.ResponseRecorder, []*http.Cookie) {
	t.Helper()
	r := httptest.NewRequest("GET", "https://api.example.com/auth/csrf-token", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	CSRFToken(cfg)(okHandler()).ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	merged := map[string]*http.Cookie{}
	for _, c := range cookies {
		merged[c.Name] = c
	}
	for _, c := range w.Result().Cookies() {
		merged[c.Name] = c
	}
	var result []*http.Cookie
	for _, c := range merged {
		result = append(result, c)
	}
	return w, result
}

// csrfRequestCookie models the Cookie request header, which has no response attributes.
func csrfRequestCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value} //nolint:gosec // G124: inbound cookie fixture; response attributes are tested separately.
}

func csrfCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}
func csrfMutation(cfg *CSRFTokenConfig, cookies []*http.Cookie, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://api.example.com/action", nil)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	r.Header.Set("X-CSRF-Token", token)
	w := httptest.NewRecorder()
	CSRFToken(cfg)(okHandler()).ServeHTTP(w, r)
	return w
}

func TestCSRFToken_FailsClosedWithoutConfiguration(t *testing.T) {
	for _, cfg := range []*CSRFTokenConfig{nil, {}} {
		for _, method := range []string{"GET", "POST"} {
			t.Run(fmt.Sprintf("%s/config-%d", method, len(cfgSecret(cfg))), func(t *testing.T) {
				w := httptest.NewRecorder()
				CSRFToken(cfg)(okHandler()).ServeHTTP(w, httptest.NewRequest(method, "/", nil))
				if w.Code != 500 {
					t.Fatalf("status=%d", w.Code)
				}
			})
		}
	}
}
func cfgSecret(c *CSRFTokenConfig) []byte {
	if c == nil {
		return nil
	}
	return c.Secret
}

func TestCSRFToken_CookieTransport(t *testing.T) {
	for _, sameSite := range []http.SameSite{http.SameSiteLaxMode, http.SameSiteStrictMode, http.SameSiteNoneMode} {
		t.Run(fmt.Sprintf("SameSite-%d", sameSite), func(t *testing.T) {
			cfg := testCSRFConfig()
			cfg.CookieSecure = true
			cfg.CookieSameSite = sameSite
			w, cookies := csrfBootstrap(t, cfg)
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("bootstrap cacheable")
			}
			for _, c := range cookies {
				if !c.HttpOnly || !c.Secure || c.Domain != "" || c.Path != "/" || c.SameSite != sameSite {
					t.Fatalf("cookie=%+v", c)
				}
			}
			if csrfCookie(cookies, "__Host-goauth_browser") == nil {
				t.Fatal("missing protected browser binding")
			}
		})
	}
}

func TestCSRFToken_Validation(t *testing.T) {
	cfg := testCSRFConfig()
	_, cookies := csrfBootstrap(t, cfg)
	token := csrfCookie(cookies, "_csrf").Value
	cases := []struct {
		name    string
		cookies []*http.Cookie
		token   string
		want    int
		code    string
	}{
		{"matching", cookies, token, 200, ""},
		{"missing cookies", nil, token, 403, "csrf_token_missing"},
		{"missing header", cookies, "", 403, "csrf_token_missing"},
		{"mismatch", cookies, "other", 403, "csrf_token_mismatch"},
		{"missing browser binding", []*http.Cookie{csrfCookie(cookies, "_csrf")}, token, 403, "csrf_token_invalid"},
		{"forged token", []*http.Cookie{csrfRequestCookie("_csrf", "forged.signature"), csrfCookie(cookies, "_goauth_browser")}, "forged.signature", 403, "csrf_token_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := csrfMutation(cfg, tc.cookies, tc.token)
			if w.Code != tc.want || !strings.Contains(w.Body.String(), tc.code) {
				t.Fatalf("%d %s", w.Code, w.Body.String())
			}
			if tc.want == 200 && len(w.Result().Cookies()) != 0 {
				t.Fatal("ordinary mutation rotated token")
			}
		})
	}
}

func TestCSRFToken_RepairsInvalidAndObsoleteCookies(t *testing.T) {
	cfg := testCSRFConfig()
	_, cookies := csrfBootstrap(t, cfg)
	original := csrfCookie(cookies, "_csrf").Value
	w, same := csrfBootstrap(t, cfg, cookies...)
	if len(w.Result().Cookies()) != 0 || csrfCookie(same, "_csrf").Value != original {
		t.Fatal("valid bootstrap rotated token")
	}
	for _, c := range cookies {
		if c.Name == "_csrf" {
			c.Value = "stale.token"
		}
	}
	_, repaired := csrfBootstrap(t, cfg, cookies...)
	token := csrfCookie(repaired, "_csrf").Value
	if token == "stale.token" || csrfMutation(cfg, repaired, token).Code != 200 {
		t.Fatal("invalid cookie not repaired")
	}
	other := testCSRFConfig()
	other.Secret = []byte(strings.Repeat("x", 32))
	_, rotated := csrfBootstrap(t, other, repaired...)
	if csrfMutation(other, rotated, csrfCookie(rotated, "_csrf").Value).Code != 200 {
		t.Fatal("root-key rotation stuck client")
	}
}

func TestCSRFToken_DifferentBrowserCannotReuseToken(t *testing.T) {
	cfg := testCSRFConfig()
	_, first := csrfBootstrap(t, cfg)
	_, second := csrfBootstrap(t, cfg)
	token := csrfCookie(first, "_csrf").Value
	for _, c := range second {
		if c.Name == "_csrf" {
			c.Value = token
		}
	}
	if w := csrfMutation(cfg, second, token); w.Code != 403 {
		t.Fatalf("cross-browser token accepted: %d", w.Code)
	}
}

type csrfSessions struct {
	session *domain.Session
	user    *domain.User
	err     error
	reads   int
}

func (s *csrfSessions) GetByTokenHashWithUser(context.Context, string) (*domain.Session, *domain.User, error) {
	s.reads++
	return s.session, s.user, s.err
}
func (s *csrfSessions) GetByRefreshHash(context.Context, string) (*domain.Session, error) {
	return s.session, s.err
}
func (s *csrfSessions) GetByPreviousRefreshHash(context.Context, string) (*domain.Session, error) {
	return s.session, s.err
}

func TestCSRFToken_SessionBindingSurvivesRefreshButNotAnotherSession(t *testing.T) {
	store := &csrfSessions{session: &domain.Session{ID: "first"}, user: &domain.User{ID: "user"}}
	cfg := testCSRFConfig()
	cfg.Sessions = store
	cfg.SessionCookie = "session"
	cfg.RefreshCookie = "refresh"
	_, cookies := csrfBootstrap(t, cfg, csrfRequestCookie("session", "access"))
	token := csrfCookie(cookies, "_csrf").Value
	if w := csrfMutation(cfg, cookies, token); w.Code != 200 {
		t.Fatalf("session token rejected: %d", w.Code)
	}
	for _, c := range cookies {
		if c.Name == "session" {
			c.Value = "rotated-access"
		}
	}
	if w := csrfMutation(cfg, cookies, token); w.Code != 200 {
		t.Fatal("refresh changed stable CSRF binding")
	}
	store.session = &domain.Session{ID: "second"}
	if w := csrfMutation(cfg, cookies, token); w.Code != 403 {
		t.Fatal("another session reused CSRF token")
	}
	_, repaired := csrfBootstrap(t, cfg, cookies...)
	if csrfMutation(cfg, repaired, csrfCookie(repaired, "_csrf").Value).Code != 200 {
		t.Fatal("new session bootstrap failed")
	}
}

func TestCSRFToken_BackendFailureFailsClosed(t *testing.T) {
	cfg := testCSRFConfig()
	cfg.SessionCookie = "session"
	cfg.Sessions = &csrfSessions{err: errors.New("database unavailable")}
	w := httptest.NewRecorder()
	CSRFToken(cfg)(okHandler()).ServeHTTP(w, func() *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(csrfRequestCookie("session", "access"))
		return r
	}())
	if w.Code != 500 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestRotateCSRFToken_AuthenticationLifecycle(t *testing.T) {
	cfg := testCSRFConfig()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/login", nil)
	if err := SetAuthenticationCookies(w, r, DefaultCookieSettings(), cfg, "session-id", "access", "refresh"); err != nil {
		t.Fatal(err)
	}
	token := w.Header().Get("X-CSRF-Token")
	if !verifyCSRFToken(token, cfg.Secret, "session:session-id") {
		t.Fatal("login token not session-bound")
	}
	w = httptest.NewRecorder()
	if err := ClearAuthenticationCookies(w, r, DefaultCookieSettings(), cfg); err != nil {
		t.Fatal(err)
	}
	cookies := w.Result().Cookies()
	browser := csrfCookie(cookies, "_goauth_browser")
	if browser == nil {
		t.Fatal("logout did not create anonymous binding")
	}
	if !verifyCSRFToken(w.Header().Get("X-CSRF-Token"), cfg.Secret, "browser:"+browser.Value) {
		t.Fatal("logout did not replace session token")
	}
	for _, c := range cookies {
		if c.Name == "goauth_session" || c.Name == "goauth_refresh" {
			if c.MaxAge != -1 {
				t.Fatal("credentials not cleared")
			}
		}
	}
	if err := RotateCSRFToken(httptest.NewRecorder(), r, nil); err == nil {
		t.Fatal("nil rotation silently succeeded")
	}
}

func TestCSRFToken_ContextOnSafeAndUnsafeMethods(t *testing.T) {
	cfg := testCSRFConfig()
	_, cookies := csrfBootstrap(t, cfg)
	token := csrfCookie(cookies, "_csrf").Value
	for _, method := range []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"} {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/", nil)
			for _, c := range cookies {
				r.AddCookie(c)
			}
			r.Header.Set("X-CSRF-Token", token)
			w := httptest.NewRecorder()
			CSRFToken(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if CSRFTokenFromContext(r.Context()) != token {
					t.Fatal("missing request token")
				}
				w.WriteHeader(200)
			})).ServeHTTP(w, r)
			if w.Code != 200 {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
}

func TestRotateCSRFToken_RebindsAfterSessionRevocation(t *testing.T) {
	store := &csrfSessions{session: &domain.Session{ID: "revoked-after-check"}, user: &domain.User{ID: "user"}}
	cfg := testCSRFConfig()
	cfg.SessionCookie = "session"
	cfg.Sessions = store
	_, cookies := csrfBootstrap(t, cfg, csrfRequestCookie("session", "access"))
	req := httptest.NewRequest("POST", "/reset-password", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	req.Header.Set(CSRFHeaderName, csrfCookie(cookies, "_csrf").Value)
	response := httptest.NewRecorder()
	CSRFToken(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		store.session = nil // the credential operation committed revocation
		if err := RotateCSRFToken(w, r, cfg); err != nil {
			t.Fatal(err)
		}
	})).ServeHTTP(response, req)
	binding := csrfCookie(response.Result().Cookies(), "_goauth_browser")
	if binding == nil || !verifyCSRFToken(response.Header().Get(CSRFHeaderName), cfg.Secret, "browser:"+binding.Value) {
		t.Fatal("rotation retained a deleted session's binding")
	}
}

func TestCSRFToken_SnapshotRequiresSessionValidation(t *testing.T) {
	store := &csrfSessions{session: &domain.Session{ID: "expired"}, user: &domain.User{ID: "user"}}
	for _, validate := range []bool{false, true} {
		cfg := testCSRFConfig()
		cfg.Sessions, cfg.SessionCookie = store, "session"
		if validate {
			cfg.ValidateSession = func(*domain.Session) error { return domain.ErrSessionExpired }
		}
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(csrfRequestCookie("session", "access"))
		response := httptest.NewRecorder()
		CSRFToken(cfg)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			snapshot, found := r.Context().Value(sessionSnapshotKey{}).(sessionSnapshot)
			if found != validate {
				t.Fatalf("snapshot reusable without policy validation: %v", found)
			}
			if validate && !errors.Is(snapshot.err, domain.ErrSessionExpired) {
				t.Fatal("snapshot lost rejection")
			}
		})).ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d", response.Code)
		}
	}
}
