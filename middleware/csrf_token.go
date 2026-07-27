package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
)

// CSRFTokenConfig configures double-submit cookie CSRF token protection.
//
// When non-nil, a random token is set in a cookie on safe methods (GET/HEAD/OPTIONS)
// and validated against the X-CSRF-Token header on state-changing methods
// (POST/PUT/PATCH/DELETE). The middleware does NOT rotate the token — rotation
// happens only in handlers that change auth credentials or session lifecycle
// (login, logout, password change) via the RotateCSRFToken helper.
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
	TokenLength   int            // bytes, default 32
	CookieName    string         // default "_csrf"
	HeaderName    string         // default "X-CSRF-Token"
	CookiePath    string         // default "/"
	CookieSecure  bool           // should match session cookie secure flag; auto-derived from BaseURL in goauth.New
	CookieSameSite http.SameSite // default Lax; cross-site deploys MUST set None + CookieSecure=true
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
// new token and sets it. If the cookie already exists, passes through without
// overwriting (no rotation).
//
// On state-changing methods (POST/PUT/PATCH/DELETE): validates that the cookie
// value matches the X-CSRF-Token header. Returns 403 if missing or mismatched.
// Does NOT rotate the token — use RotateCSRFToken in handlers for that.
func CSRFToken(cfg *CSRFTokenConfig) func(http.Handler) http.Handler {
	if cfg == nil {
		return func(next http.Handler) http.Handler { return next }
	}

	cfg.defaults()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET", "HEAD", "OPTIONS":
				if _, err := r.Cookie(cfg.CookieName); err != nil {
					token, err := generateCSRFToken(cfg.TokenLength)
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

			if cookie.Value != header {
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
// This function is a no-op if cfg is nil.
func RotateCSRFToken(w http.ResponseWriter, cfg *CSRFTokenConfig) {
	if cfg == nil {
		return
	}
	token, err := generateCSRFToken(cfg.TokenLength)
	if err != nil {
		return
	}
	setCSRFCookie(w, cfg, token)
}

func generateCSRFToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
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
