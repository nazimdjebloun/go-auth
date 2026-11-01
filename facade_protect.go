package goauth

import "net/http"

// Protect builds the complete browser security chain for an application route:
// CORS, the configured route rate limit, signed double-submit and origin checks,
// then session authentication and current email-verification policy.
//
// pattern uses ServeMux syntax, for example "POST /widgets/{id}". The wrapper
// populates Request.Pattern and PathValue even on a third-party router. Invalid
// patterns or nil handlers panic at setup; requests outside the pattern get 404.
// Register OPTIONS separately on method-based routers so preflights reach this
// wrapper. ServeMux callers may apply Auth.CORS to the complete mux instead.
//
// Authorization remains explicit: pass RequireAppPermission, RequireAdmin or
// RequireOrg around next to run those checks after authentication.
func (a *Auth) Protect(pattern string, next http.Handler) http.Handler {
	if next == nil {
		panic("goauth: Protect requires a handler")
	}
	limited := a.RateLimitWithPattern(pattern)
	mux := http.NewServeMux()
	mux.Handle(pattern, a.RequireCSRF(a.RequireAuth(next)))
	return a.CORS(limited(mux))
}
