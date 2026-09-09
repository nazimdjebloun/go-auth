package goauth

import (
	"fmt"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// RequireAuth protects a consumer route with the same session validation
// (including transparent refresh) that the built-in auth routes use. On
// success the user and session are placed in the request context — read
// them with middleware.GetUserFromContext and middleware.GetSessionFromContext.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return a.authMW(next)
}

// RequireAdmin protects a consumer route with the admin role check used by
// the built-in /admin routes. Wrap with RequireAuth first: the check reads
// the user from the context RequireAuth populates.
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

// RequireOrg protects a consumer route with an org membership check plus a
// minimum role, using the same org repository and auth context as the built-in
// org routes. It resolves the org from the {orgID} path segment, falling back
// to the org_id query parameter, and must run after RequireAuth.
//
// When organizations are disabled the returned middleware rejects every
// request with 503 — add goauth.WithOrganizations(goauth.OrganizationConfig{
// Enable: true}) to enable them.
func (a *Auth) RequireOrg(role domain.OrgRole) func(http.Handler) http.Handler {
	if !role.IsValid() {
		panic(fmt.Sprintf(
			"goauth: invalid org role %q — use domain.OrgRoleMember, domain.OrgRoleAdmin, or domain.OrgRoleOwner",
			role,
		))
	}
	if a.orgService == nil {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error":"organizations_disabled","message":"Organizations are not enabled — add goauth.WithOrganizations(goauth.OrganizationConfig{Enable: true})"}`, http.StatusServiceUnavailable)
			})
		}
	}
	roleMW := middleware.RequireOrgRole(role)
	return func(next http.Handler) http.Handler {
		return a.orgMemberMW(roleMW(next))
	}
}

// RequireActiveOrg protects a consumer route with an org membership check
// plus a minimum role, same as RequireOrg, but resolves the org from the
// caller's session (session.ActiveOrgID/ActiveOrgRole, set via SetActiveOrg)
// instead of an {orgID} path segment. Use this for routes that operate
// implicitly on "the org I'm currently working in" — most of an app's own
// business routes (projects, tasks, and the like) — reserving RequireOrg for
// routes that name a specific org explicitly. Must run after RequireAuth.
//
// When organizations are disabled the returned middleware rejects every
// request with 503 — add goauth.WithOrganizations(goauth.OrganizationConfig{
// Enable: true}) to enable them.
func (a *Auth) RequireActiveOrg(role domain.OrgRole) func(http.Handler) http.Handler {
	if !role.IsValid() {
		panic(fmt.Sprintf(
			"goauth: invalid org role %q — use domain.OrgRoleMember, domain.OrgRoleAdmin, or domain.OrgRoleOwner",
			role,
		))
	}
	if a.orgService == nil {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error":"organizations_disabled","message":"Organizations are not enabled — add goauth.WithOrganizations(goauth.OrganizationConfig{Enable: true})"}`, http.StatusServiceUnavailable)
			})
		}
	}
	return middleware.RequireActiveOrg(role)
}

// RequireCSRF applies the same double-submit CSRF verification the built-in
// mutating routes use to a consumer route — checks the X-CSRF-Token header
// against the signed _csrf cookie set by the priming GET request. A no-op
// (passthrough) if the double-submit CSRF layer is disabled
// (SecurityConfig.DisableCSRFToken). The routes mounted by Mount already have
// this baked in — this is for your own routes only.
func (a *Auth) RequireCSRF(next http.Handler) http.Handler {
	return middleware.CSRFToken(a.cfg.security.CSRFToken)(next)
}

// Session cookie accessors.

// SetSessionCookies writes the session and refresh cookies for a newly
// issued token pair, using the configured cookie settings. Pair it with a
// custom handler that calls a.Services.Auth.Login (or Register) directly —
// that call returns raw tokens with no cookies set; this is how you turn
// them into the same cookies the built-in handlers issue. A non-empty
// refreshToken is required to also write the refresh cookie; pass "" to
// skip it (mirrors the built-in handlers' behavior when no refresh token
// was issued).
//
// This does not rotate the CSRF token — call RotateCSRFToken separately if
// your handler needs the same "session issued" ceremony the built-in login
// handlers perform.
func (a *Auth) SetSessionCookies(w http.ResponseWriter, sessionToken, refreshToken string) {
	middleware.SetSessionCookie(w, a.cookies, sessionToken)
	middleware.SetRefreshCookie(w, a.cookies, refreshToken)
}

// ClearSessionCookies expires both the session and refresh cookies. Pair it
// with a custom handler that revokes the session itself via
// a.Services.Session.Revoke.
func (a *Auth) ClearSessionCookies(w http.ResponseWriter) {
	middleware.ClearSessionCookie(w, a.cookies)
	middleware.ClearRefreshCookie(w, a.cookies)
}

// RotateCSRFToken issues a fresh CSRF token cookie, using the configured
// CSRF settings. A no-op if the double-submit CSRF layer is disabled
// (SecurityConfig.DisableCSRFToken). Call this alongside SetSessionCookies
// in a custom login handler to match the built-in handlers, which rotate
// the CSRF token on every login/logout.
func (a *Auth) RotateCSRFToken(w http.ResponseWriter) {
	middleware.RotateCSRFToken(w, a.cfg.security.CSRFToken)
}
