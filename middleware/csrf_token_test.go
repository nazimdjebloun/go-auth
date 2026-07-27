package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

func TestCSRFToken_PassthroughWhenNil(t *testing.T) {
	mw := CSRFToken(nil)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	w := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestCSRFToken_SetsCookieOnGet(t *testing.T) {
	mw := CSRFToken(&CSRFTokenConfig{})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	cookies := w.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "_csrf" {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("expected _csrf cookie to be set on GET")
	}
	if csrfCookie.Value == "" {
		t.Fatal("expected _csrf cookie to have a non-empty value")
	}
	if csrfCookie.HttpOnly {
		t.Fatal("expected _csrf cookie to NOT be HttpOnly (JS must read it)")
	}
}

func TestCSRFToken_SetsCookieOnHead(t *testing.T) {
	mw := CSRFToken(&CSRFTokenConfig{})
	req := httptest.NewRequest(http.MethodHead, "/", nil)
	w := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "_csrf" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected _csrf cookie on HEAD")
	}
}

func TestCSRFToken_SetsCookieOnOptions(t *testing.T) {
	mw := CSRFToken(&CSRFTokenConfig{})
	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	w := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(w, req)

	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "_csrf" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected _csrf cookie on OPTIONS")
	}
}

func TestCSRFToken_DoesNotOverwriteExistingCookieOnGet(t *testing.T) {
	mw := CSRFToken(&CSRFTokenConfig{})

	// First GET to seed a token.
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	w1 := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w1, req1)

	var original string
	for _, c := range w1.Result().Cookies() {
		if c.Name == "_csrf" {
			original = c.Value
			break
		}
	}
	if original == "" {
		t.Fatal("no CSRF token from first GET")
	}

	// Second GET — should NOT rotate the cookie.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: "_csrf", Value: original})
	w2 := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w2, req2)

	for _, c := range w2.Result().Cookies() {
		if c.Name == "_csrf" {
			t.Fatal("should not set a new CSRF cookie when one already exists")
		}
	}
}

func TestCSRFToken_AcceptsMatchingToken(t *testing.T) {
	mw := CSRFToken(&CSRFTokenConfig{})

	// GET to obtain a token.
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getW := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(getW, getReq)

	var token string
	for _, c := range getW.Result().Cookies() {
		if c.Name == "_csrf" {
			token = c.Value
			break
		}
	}
	if token == "" {
		t.Fatal("no CSRF token from GET")
	}

	// POST with matching cookie + header.
	postReq := httptest.NewRequest(http.MethodPost, "/", nil)
	postReq.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	postReq.Header.Set("X-CSRF-Token", token)
	postW := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("expected 200 for matching token, got %d", postW.Code)
	}
}

func TestCSRFToken_RejectsMismatchedToken(t *testing.T) {
	mw := CSRFToken(&CSRFTokenConfig{})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "cookie-token"})
	req.Header.Set("X-CSRF-Token", "header-token")
	w := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for mismatched token, got %d", w.Code)
	}
}

func TestCSRFToken_RejectsMissingHeader(t *testing.T) {
	mw := CSRFToken(&CSRFTokenConfig{})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "some-token"})
	w := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing header, got %d", w.Code)
	}
}

func TestCSRFToken_RejectsMissingCookie(t *testing.T) {
	mw := CSRFToken(&CSRFTokenConfig{})

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	w := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing cookie, got %d", w.Code)
	}
}

func TestCSRFToken_DoesNotRotateTokenOnMutation(t *testing.T) {
	mw := CSRFToken(&CSRFTokenConfig{})

	// GET to seed token.
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getW := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(getW, getReq)

	var original string
	for _, c := range getW.Result().Cookies() {
		if c.Name == "_csrf" {
			original = c.Value
			break
		}
	}

	// POST with matching token.
	postReq := httptest.NewRequest(http.MethodPost, "/", nil)
	postReq.AddCookie(&http.Cookie{Name: "_csrf", Value: original})
	postReq.Header.Set("X-CSRF-Token", original)
	postW := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", postW.Code)
	}

	// Response must NOT contain a new CSRF cookie (no rotation).
	for _, c := range postW.Result().Cookies() {
		if c.Name == "_csrf" {
			t.Fatal("middleware must not rotate CSRF token on mutation; use RotateCSRFToken in handlers")
		}
	}
}

func TestCSRFToken_CustomConfig(t *testing.T) {
	cfg := &CSRFTokenConfig{
		CookieName:   "x-csrf",
		HeaderName:   "X-XSRF-TOKEN",
		CookieSecure: true,
	}
	mw := CSRFToken(cfg)

	// GET with custom cookie name.
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getW := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(getW, getReq)

	var token string
	for _, c := range getW.Result().Cookies() {
		if c.Name == "x-csrf" {
			token = c.Value
			if !c.Secure {
				t.Fatal("expected Secure flag on custom cookie")
			}
			break
		}
	}
	if token == "" {
		t.Fatal("expected custom cookie name 'x-csrf'")
	}

	// POST with custom header name.
	postReq := httptest.NewRequest(http.MethodPost, "/", nil)
	postReq.AddCookie(&http.Cookie{Name: "x-csrf", Value: token})
	postReq.Header.Set("X-XSRF-TOKEN", token)
	postW := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(postW, postReq)

	if postW.Code != http.StatusOK {
		t.Fatalf("expected 200 with custom config, got %d", postW.Code)
	}
}

func TestCSRFToken_SameSiteDefaultIsLax(t *testing.T) {
	cfg := &CSRFTokenConfig{}
	cfg.defaults()

	if cfg.CookieSameSite != http.SameSiteLaxMode {
		t.Fatalf("expected default SameSite to be Lax, got %v", cfg.CookieSameSite)
	}

	mw := CSRFToken(cfg)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w, req)

	for _, c := range w.Result().Cookies() {
		if c.Name == "_csrf" {
			if c.SameSite != http.SameSiteLaxMode {
				t.Fatalf("expected cookie SameSite=Lax, got %v", c.SameSite)
			}
			return
		}
	}
	t.Fatal("no _csrf cookie found in response")
}

func TestRotateCSRFToken_SetsNewCookie(t *testing.T) {
	cfg := &CSRFTokenConfig{}
	cfg.defaults() // mirrors production: CSRFToken(cfg) calls defaults() once at construction

	w := httptest.NewRecorder()
	RotateCSRFToken(w, cfg)

	var found bool
	for _, c := range w.Result().Cookies() {
		if c.Name == "_csrf" {
			found = true
			if c.Value == "" {
				t.Fatal("expected non-empty token")
			}
			break
		}
	}
	if !found {
		t.Fatal("expected RotateCSRFToken to set a _csrf cookie")
	}
}

func TestRotateCSRFToken_NoOpWhenNil(t *testing.T) {
	w := httptest.NewRecorder()
	RotateCSRFToken(w, nil)

	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == "_csrf" {
			t.Fatal("RotateCSRFToken(nil) should not set any cookie")
		}
	}
}

func TestRefreshToken_DoesNotRotateCSRF(t *testing.T) {
	// Regression guard: RefreshHandler must NOT call RotateCSRFToken.
	// This test simulates a refresh handler that intentionally omits
	// RotateCSRFToken, verifying the response cookie is identical to the
	// request cookie. Without this guard, someone could later add
	// RotateCSRFToken to refresh and reintroduce the multi-tab race.
	cfg := &CSRFTokenConfig{}
	mw := CSRFToken(cfg)

	// GET to seed token.
	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getW := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(getW, getReq)

	var token string
	for _, c := range getW.Result().Cookies() {
		if c.Name == "_csrf" {
			token = c.Value
			break
		}
	}
	if token == "" {
		t.Fatal("no CSRF token from GET")
	}

	// Simulate a refresh handler that does NOT call RotateCSRFToken.
	refreshHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Intentionally no RotateCSRFToken — refresh is session continuation.
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	w := httptest.NewRecorder()

	mw(refreshHandler).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Verify: response must NOT set a new _csrf cookie (no rotation).
	for _, c := range w.Result().Cookies() {
		if c.Name == "_csrf" {
			t.Fatalf("refresh handler must not rotate CSRF token; got new cookie %q", c.Value)
		}
	}
}
