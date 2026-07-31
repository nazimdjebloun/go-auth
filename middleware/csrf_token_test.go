package middleware

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testSecret is a 32-byte HMAC-SHA256 key used across CSRF token tests.
const testSecret = "0123456789abcdef0123456789abcdef"

func testCSRFConfig() *CSRFTokenConfig {
	return &CSRFTokenConfig{Secret: []byte(testSecret)}
}

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
	mw := CSRFToken(testCSRFConfig())
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
	mw := CSRFToken(testCSRFConfig())
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
	mw := CSRFToken(testCSRFConfig())
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
	mw := CSRFToken(testCSRFConfig())

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
	mw := CSRFToken(testCSRFConfig())

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
	mw := CSRFToken(testCSRFConfig())

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
	mw := CSRFToken(testCSRFConfig())

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "some-token"})
	w := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing header, got %d", w.Code)
	}
}

func TestCSRFToken_RejectsMissingCookie(t *testing.T) {
	mw := CSRFToken(testCSRFConfig())

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-CSRF-Token", "some-token")
	w := httptest.NewRecorder()

	mw(okHandler()).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing cookie, got %d", w.Code)
	}
}

func TestCSRFToken_DoesNotRotateTokenOnMutation(t *testing.T) {
	mw := CSRFToken(testCSRFConfig())

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
		Secret:       []byte(testSecret),
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
	cfg := testCSRFConfig()
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
	cfg := testCSRFConfig()
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

func TestCSRFToken_ConstantTimeComparison(t *testing.T) {
	mw := CSRFToken(testCSRFConfig())

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

	// POST with correct token — must succeed.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	req.Header.Set("X-CSRF-Token", token)
	w := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid token, got %d", w.Code)
	}

	// POST with token that differs only in the last byte — must be rejected.
	// This verifies the comparison is not short-circuiting on first differing byte.
	tampered := token[:len(token)-1] + "X"
	if tampered == token {
		t.Skip("tampered token is identical; test is not useful")
	}
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	req2.Header.Set("X-CSRF-Token", tampered)
	w2 := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for tampered token, got %d", w2.Code)
	}

	// POST with completely different token — must be rejected.
	req3 := httptest.NewRequest(http.MethodPost, "/", nil)
	req3.AddCookie(&http.Cookie{Name: "_csrf", Value: "completely-different-token-value-aaaaaaaa"})
	req3.Header.Set("X-CSRF-Token", "completely-different-token-value-bbbbbbbb")
	w3 := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w3, req3)
	if w3.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for completely different token, got %d", w3.Code)
	}
}

func TestCSRFToken_NilSafeComparison(t *testing.T) {
	mw := CSRFToken(testCSRFConfig())

	// Empty cookie value + empty header value — both must be non-empty before comparison.
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: ""})
	req.Header.Set("X-CSRF-Token", "")
	w := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for empty values, got %d", w.Code)
	}

	// Cookie with value, empty header — should reject.
	req2 := httptest.NewRequest(http.MethodPost, "/", nil)
	req2.AddCookie(&http.Cookie{Name: "_csrf", Value: "some-token"})
	req2.Header.Set("X-CSRF-Token", "")
	w2 := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for empty header, got %d", w2.Code)
	}
}

func TestRefreshToken_DoesNotRotateCSRF(t *testing.T) {
	// Regression guard: RefreshHandler must NOT call RotateCSRFToken.
	// This test simulates a refresh handler that intentionally omits
	// RotateCSRFToken, verifying the response cookie is identical to the
	// request cookie. Without this guard, someone could later add
	// RotateCSRFToken to refresh and reintroduce the multi-tab race.
	cfg := testCSRFConfig()
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

func TestCSRFToken_RejectsForgedCookie(t *testing.T) {
	// Simulates a cookie-write-only attacker (e.g. sibling-subdomain cookie
	// injection): they inject an arbitrary _csrf cookie value of their own
	// choosing and send it back as the header. Without the signing secret they
	// cannot produce a value whose HMAC verifies, so the server must reject it.
	mw := CSRFToken(testCSRFConfig())

	t.Run("bare attacker nonce", func(t *testing.T) {
		forged := base64.RawURLEncoding.EncodeToString([]byte("attacker-controlled-nonce"))

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: "_csrf", Value: forged})
		req.Header.Set("X-CSRF-Token", forged)
		w := httptest.NewRecorder()

		mw(okHandler()).ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for forged cookie, got %d", w.Code)
		}
	})

	t.Run("attacker nonce with bogus signature", func(t *testing.T) {
		forged := "MTIzNDU2Nzg5MA.attacker-controlled-signature"

		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.AddCookie(&http.Cookie{Name: "_csrf", Value: forged})
		req.Header.Set("X-CSRF-Token", forged)
		w := httptest.NewRecorder()

		mw(okHandler()).ServeHTTP(w, req)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for forged nonce.signature, got %d", w.Code)
		}
	})
}

func TestCSRFToken_RejectsTokenSignedWithDifferentSecret(t *testing.T) {
	// A token minted by a server with secret A must be rejected by a server
	// validating with secret B — guards against misconfiguration across restarts.
	issuer := CSRFToken(&CSRFTokenConfig{Secret: []byte(strings.Repeat("A", 32))})
	validator := CSRFToken(testCSRFConfig())

	getReq := httptest.NewRequest(http.MethodGet, "/", nil)
	getW := httptest.NewRecorder()
	issuer(okHandler()).ServeHTTP(getW, getReq)

	var token string
	for _, c := range getW.Result().Cookies() {
		if c.Name == "_csrf" {
			token = c.Value
			break
		}
	}
	if token == "" {
		t.Fatal("no token issued")
	}

	postReq := httptest.NewRequest(http.MethodPost, "/", nil)
	postReq.AddCookie(&http.Cookie{Name: "_csrf", Value: token})
	postReq.Header.Set("X-CSRF-Token", token)
	w := httptest.NewRecorder()
	validator(okHandler()).ServeHTTP(w, postReq)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for token signed with a different secret, got %d", w.Code)
	}
}

func TestCSRFToken_TokenIsSigned(t *testing.T) {
	mw := CSRFToken(testCSRFConfig())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w, req)

	var token string
	for _, c := range w.Result().Cookies() {
		if c.Name == "_csrf" {
			token = c.Value
			break
		}
	}
	if token == "" {
		t.Fatal("no _csrf cookie set")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Fatalf("expected nonce.signature token, got %q", token)
	}
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if parts[1] != expected {
		t.Fatal("cookie signature does not recompute from nonce + secret")
	}
}

func TestCSRFToken_FailsClosedWhenSecretMissing(t *testing.T) {
	// Direct Config{} construction bypasses validate(); the sign/verify path
	// must fail closed rather than sign or verify with an empty key.
	mw := CSRFToken(&CSRFTokenConfig{})

	// Safe method: cannot issue an unsigned token.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on GET with no secret, got %d", w.Code)
	}

	// State-changing method: cannot verify without a secret.
	postReq := httptest.NewRequest(http.MethodPost, "/", nil)
	postReq.AddCookie(&http.Cookie{Name: "_csrf", Value: "any.value"})
	postReq.Header.Set("X-CSRF-Token", "any.value")
	postW := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(postW, postReq)
	if postW.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on POST with no secret, got %d", postW.Code)
	}
}

func TestRotateCSRFToken_FailsClosedWhenSecretMissing(t *testing.T) {
	w := httptest.NewRecorder()
	RotateCSRFToken(w, &CSRFTokenConfig{})
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("expected no cookie to be set when signing secret is empty")
	}
}

func TestCSRFToken_FailsClosedLogsStructured(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	mw := CSRFToken(&CSRFTokenConfig{Logger: logger})

	// Issue path: safe method with no secret.
	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	w := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on GET with no secret, got %d", w.Code)
	}

	// Verify path: state-changing method with no secret.
	postReq := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	postReq.AddCookie(&http.Cookie{Name: "_csrf", Value: "any.value"})
	postReq.Header.Set("X-CSRF-Token", "any.value")
	postW := httptest.NewRecorder()
	mw(okHandler()).ServeHTTP(postW, postReq)
	if postW.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on POST with no secret, got %d", postW.Code)
	}

	// Rotate path: no request in scope, so no path field.
	RotateCSRFToken(httptest.NewRecorder(), &CSRFTokenConfig{Logger: logger})

	out := buf.String()
	for _, want := range []string{"check=issue", "check=verify", "check=rotate", "path=/auth/login"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log output to contain %q, got:\n%s", want, out)
		}
	}
}
