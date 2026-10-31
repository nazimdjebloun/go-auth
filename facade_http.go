package goauth

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/middleware"
)

// RequireAuth protects a consumer route with the same session validation
// (including transparent refresh) that the built-in auth routes use. On
// success the user and session are placed in the request context — read
// them with middleware.GetUserFromContext and middleware.GetSessionFromContext.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return a.authMW(next)
}

// RequireAdmin applies the current admin role and second-factor requirements
// used by built-in /admin routes. Wrap with RequireAuth first so the user and
// session are available in the request context.
func (a *Auth) RequireAdmin(next http.Handler) http.Handler {
	return a.adminMW(next)
}

// RateLimit applies the configured rate limiter to a consumer route. The
// routes mounted by Mount already have rate limiting baked in — this is for
// your own routes only.
func (a *Auth) RateLimit(next http.Handler) http.Handler {
	return a.rateLimitMW(next)
}

// RateLimitWithPattern is RateLimit for a consumer route mounted on a router
// that doesn't populate http.Request.Pattern — chi, gorilla/mux, echo, and
// anything that isn't net/http's ServeMux.
//
// Counters are keyed on the route pattern, not the request path, so a route
// with a path parameter can't be turned into an unlimited supply of fresh
// counters. Where the pattern isn't discoverable, every such route shares one
// fallback counter per client; naming it here gives the route its own:
//
//	r.Post("/widgets/{id}/publish",
//	    auth.RateLimitWithPattern("POST /widgets/{id}/publish")(publish).ServeHTTP)
//
// The string only has to be stable and one-per-route — it isn't parsed. To
// give the route its own limit as well as its own counter, add the same
// string to the rate table with WithRateLimitRoute.
//
// Don't reuse a pattern that already names one of the mounted routes: the
// pattern picks the counter, but the rate still comes from matching this
// request's own method and path, so the route would share the other route's
// counter while being charged the default rate.
func (a *Auth) RateLimitWithPattern(pattern string) func(http.Handler) http.Handler {
	return middleware.RateLimitWithPattern(a.cfg.rateLimit, pattern)
}

// CORS applies the configured CORS middleware to a consumer route. The
// routes mounted by Mount already have CORS baked in — this is for your own
// routes only.
func (a *Auth) CORS(next http.Handler) http.Handler {
	return a.corsMW(next)
}

// RequireCSRF applies mandatory signed double-submit and Origin/Referer
// verification to application routes. Mount already applies both to mutations.
func (a *Auth) RequireCSRF(next http.Handler) http.Handler {
	var trusted []string
	if a.cfg.rateLimit != nil {
		trusted = a.cfg.rateLimit.TrustedIPs
	}
	origin := middleware.OriginCheck(a.cfg.browser.AllowedOrigins, false, trusted, a.cfg.logger)
	return middleware.BrowserSession(a.cfg.logger, false)(origin(middleware.CSRFToken(a.cfg.csrf)(next)))
}

// SetSessionCookies issues session/refresh cookies and a session-bound CSRF
// token together. Supply the stable ID returned alongside the raw credentials.
func (a *Auth) SetSessionCookies(w http.ResponseWriter, r *http.Request, sessionID, sessionToken, refreshToken string) error {
	return middleware.SetAuthenticationCookies(w, r, a.cookies, a.cfg.csrf, sessionID, sessionToken, refreshToken)
}

// ClearSessionCookies clears credentials and issues anonymous browser CSRF
// protection. Revoke the session through the service before calling this.
func (a *Auth) ClearSessionCookies(w http.ResponseWriter, r *http.Request) error {
	return middleware.ClearAuthenticationCookies(w, r, a.cookies, a.cfg.csrf)
}

// RotateCSRFToken replaces CSRF protection in the current request context.
// Session issuance and clearing already perform their own rotation.
func (a *Auth) RotateCSRFToken(w http.ResponseWriter, r *http.Request) error {
	return middleware.RotateCSRFToken(w, r, a.cfg.csrf)
}
