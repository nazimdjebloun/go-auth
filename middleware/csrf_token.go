package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// CSRFTokenConfig configures double-submit cookie CSRF token protection.
//
// When non-nil, a token is set in a cookie on safe methods (GET/HEAD/OPTIONS)
// and validated against the X-CSRF-Token header on state-changing methods
// (POST/PUT/PATCH/DELETE). The middleware does NOT rotate the token — rotation
// happens only in handlers that change auth credentials or session lifecycle
// (login, logout, password change) via the RotateCSRFToken helper.
//
// Token construction: the cookie value is "nonce.signature", where nonce is
// TokenLength bytes of crypto/rand and signature is
// HMAC-SHA256(Secret, nonce), both base64url-encoded. The server verifies the
// token by recomputing the HMAC over the nonce and comparing signatures in
// constant time — it needs no lookup and no session. Because the signature is
// bound to Secret, a client that can write the _csrf cookie directly (e.g.
// sibling-subdomain cookie injection or non-HTTPS cookie injection) cannot
// produce a value that passes: they can write any nonce but cannot compute a
// matching signature without the secret. The token is deliberately NOT bound
// to the session or user ID: the priming GET /auth/csrf-token happens before
// login, when no session exists yet.
//
// Secret is populated by goauth.New from Config.Secret. It must be non-empty;
// if it is empty at the point of use the middleware fails closed (500 + a
// structured error log) rather than signing or verifying with an empty key.
// Do not set Secret
// directly — use WithSecret.
//
// The cookie is NOT HttpOnly — JavaScript must read it to include in requests.
// CSRF tokens do not protect against XSS; an attacker with XSS can fire
// same-origin requests with cookies included regardless.
//
// Cookie priming: the client MUST call GET /auth/csrf-token (or any GET to the
// API) before its first POST/PUT/PATCH/DELETE, otherwise no cookie exists and
// CSRF validation will 403. This is mandatory for cross-origin deployments
// where the first browser request is often a POST.
//
// Cross-site deployment warning: if the API and frontend are on different
// registrable domains (e.g., api.example.com vs app.example.com), you MUST
// set SameSite=None and CookieSecure=true. SameSite=Lax (the default) blocks
// the cookie on cross-site POST requests, silently 403ing every mutation.
// Same-site subdomain deployments (app.example.com / api.example.com) work
// with the default Lax or Strict.
type CSRFTokenConfig struct {
	TokenLength    int            // bytes, default 32
	CookieName     string         // default "_csrf"
	HeaderName     string         // default "X-CSRF-Token"
	CookiePath     string         // default "/"
	CookieSecure   bool           // should match session cookie secure flag; auto-derived from BaseURL in goauth.New
	CookieSameSite http.SameSite  // default Lax; cross-site deploys MUST set None + CookieSecure=true
	Secret         []byte         // HMAC-SHA256 signing key; set by goauth.New from Config.Secret
	Logger         *slog.Logger   // structured logger for fail-closed errors; defaults to slog.Default()
}

func (c *CSRFTokenConfig) defaults() {
	if c.TokenLength <= 0 {
		c.TokenLength = 32
	}
	if c.CookieName == "" {
		c.CookieName = "_csrf"
	}
	if c.HeaderName == "" {
		c.HeaderName = "X-CSRF-Token"
	}
	if c.CookiePath == "" {
		c.CookiePath = "/"
	}
	if c.CookieSameSite == 0 {
		c.CookieSameSite = http.SameSiteLaxMode
	}
}

// CSRFToken returns middleware that implements double-submit cookie CSRF protection.
// If cfg is nil, it returns a passthrough middleware (no CSRF protection).
//
// On safe methods (GET/HEAD/OPTIONS): if no _csrf cookie exists, generates a
// new signed token and sets it. If the cookie already exists, passes through
// without overwriting (no rotation).
//
// On state-changing methods (POST/PUT/PATCH/DELETE): verifies the cookie value
// is a valid signed token (HMAC recomputed over its nonce), then validates that
// the cookie value matches the X-CSRF-Token header. Returns 403 if the cookie
// is forged/invalid or the header is missing/mismatched. Returns 500 if Secret
// is empty (fail closed). Does NOT rotate the token — use RotateCSRFToken in
// handlers for that.
func CSRFToken(cfg *CSRFTokenConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	cfg.defaults()
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET", "HEAD", "OPTIONS":
				if _, err := r.Cookie(cfg.CookieName); err != nil {
					if len(cfg.Secret) == 0 {
						cfg.Logger.Error("csrf: refusing to issue token: signing secret is empty (misconfigured goauth.Config.Secret)",
							"check", "issue",
							"path", r.URL.Path,
						)
						http.Error(w, "Internal server error", http.StatusInternalServerError)
						return
					}
					token, err := generateCSRFToken(cfg.TokenLength, cfg.Secret)
					if err != nil {
						http.Error(w, "Internal server error", http.StatusInternalServerError)
						return
					}
					setCSRFCookie(w, cfg, token)
				}
				next.ServeHTTP(w, r)
				return
			}

			cookie, cookieErr := r.Cookie(cfg.CookieName)
			if cookieErr != nil || cookie.Value == "" {
				http.Error(w, "Forbidden - CSRF token missing", http.StatusForbidden)
				return
			}

			header := r.Header.Get(cfg.HeaderName)
			if header == "" {
				http.Error(w, "Forbidden - CSRF token missing", http.StatusForbidden)
				return
			}

			if len(cfg.Secret) == 0 {
				cfg.Logger.Error("csrf: refusing to verify token: signing secret is empty (misconfigured goauth.Config.Secret)",
					"check", "verify",
					"path", r.URL.Path,
				)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			if !verifyCSRFToken(cookie.Value, cfg.Secret) {
				http.Error(w, "Forbidden - CSRF token invalid", http.StatusForbidden)
				return
			}

			if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(header)) != 1 {
				http.Error(w, "Forbidden - CSRF token mismatch", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RotateCSRFToken generates a new CSRF token and sets it in the response cookie.
// Call this from handlers that change auth credentials or session lifecycle
// (login, logout, password change, etc.) to rotate the client's CSRF token.
//
// This function is a no-op if cfg is nil or if the signing secret is empty
// (the token cannot be signed, so nothing is issued; the next mutation will
// 403 or the priming GET will re-issue).
func RotateCSRFToken(w http.ResponseWriter, cfg *CSRFTokenConfig) {
	if cfg == nil {
		return
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if len(cfg.Secret) == 0 {
		logger.Error("csrf: refusing to rotate token: signing secret is empty (misconfigured goauth.Config.Secret)",
			"check", "rotate",
		)
		return
	}
	token, err := generateCSRFToken(cfg.TokenLength, cfg.Secret)
	if err != nil {
		return
	}
	setCSRFCookie(w, cfg, token)
}

// generateCSRFToken returns "base64url(nonce).base64url(HMAC-SHA256(secret, nonce))".
func generateCSRFToken(length int, secret []byte) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("csrf: signing secret is empty")
	}
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	nonceEncoded := base64.RawURLEncoding.EncodeToString(nonce)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(nonceEncoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return nonceEncoded + "." + sig, nil
}

// verifyCSRFToken recomputes HMAC-SHA256(secret, nonce) over the token's nonce
// and compares the signature in constant time. It does not enforce a minimum
// nonce length beyond requiring a well-formed "nonce.signature" pair; the HMAC
// binds the value to Secret regardless of nonce length.
func verifyCSRFToken(token string, secret []byte) bool {
	if len(secret) == 0 {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}

func setCSRFCookie(w http.ResponseWriter, cfg *CSRFTokenConfig, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    token,
		Path:     cfg.CookiePath,
		HttpOnly: false,
		Secure:   cfg.CookieSecure,
		SameSite: cfg.CookieSameSite,
		MaxAge:   0,
	})
}
