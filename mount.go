package goauth

import (
	"net/http"
	"strings"
)

// Mount registers every enabled route onto mux. It requires a real
// *http.ServeMux (Go 1.22+'s pattern syntax, e.g. "GET /admin/users/{id}")
// because route handlers read path parameters with r.PathValue, which only
// ServeMux populates — mounting the same handlers on chi, gin, echo, or any
// router that doesn't call r.SetPathValue itself will 404 or read an empty
// ID on every parameterized route, with no error at mount time. Bridge to
// another router by having it populate PathValue before calling into these
// handlers, or use Auth.RequireAuth/RequireAdmin/RequireOrg plus
// auth.Services().* directly and write your own routing layer.
func (a *Auth) Mount(mux *http.ServeMux) {
	// All middleware (CORS, rate limit, csrf token, origin check, auth, admin)
	// is already baked into a.routes — CORS outermost so preflight OPTIONS
	// short-circuits before rate limiting. Mount only registers routes; do NOT
	// wrap the mux again with a.CORS or any other middleware.
	//
	// handle registers a route and, when CORS origins are configured, also the
	// exact OPTIONS twin for the same path. OPTIONS is registered 1:1 with each
	// route go-auth owns — never a catch-all — so preflight requests for paths
	// go-auth does not own (including a consumer's own routes on a shared mux)
	// still get a normal 404/405 and never reach the CORS layer.
	preflight := len(a.cfg.security.AllowedOrigins) > 0
	preflightPaths := make(map[string]bool)
	handle := func(pattern string, h http.Handler) {
		mux.Handle(pattern, h)
		if preflight {
			// OPTIONS is registered once per path. Multiple methods may share a
			// path (GET /auth/sessions, DELETE /auth/sessions), but preflight is
			// method-agnostic, so a duplicate registration would panic. CORS
			// short-circuits OPTIONS with 204 before the handler runs, so any
			// of the shared handlers answers it correctly.
			if i := strings.IndexByte(pattern, ' '); i > 0 {
				p := pattern[i+1:]
				if !preflightPaths[p] {
					preflightPaths[p] = true
					mux.Handle("OPTIONS "+p, h)
				}
			}
		}
	}

	for _, e := range a.routes {
		handle(e.Pattern, e.Handler)
	}
}

// Handler returns the fully wrapped handler for an enabled canonical route
// pattern, such as "POST /auth/login". It returns false for disabled features
// and unknown patterns. The returned handler sets Request.Pattern to the
// canonical pattern for per-route rate limiting. A custom router must still
// set PathValue for each parameterized path segment before calling it.
func (a *Auth) Handler(pattern string) (http.Handler, bool) {
	for _, e := range a.routes {
		if e.Pattern == pattern {
			h := e.Handler
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				request := *r
				request.Pattern = pattern
				h.ServeHTTP(w, &request)
			}), true
		}
	}
	return nil, false
}
