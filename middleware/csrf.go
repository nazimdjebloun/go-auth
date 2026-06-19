package middleware

import (
	"net/http"
	"net/url"
	"strings"
)

// OriginCheck returns middleware that validates Origin or Referer headers on
// state-changing requests (POST, PUT, PATCH, DELETE) to defend against CSRF.
// When allowedOrigins contains "*" the check is skipped.
// When allowedOrigins is empty, only same-origin requests (Origin empty/missing)
// are permitted — suitable for same-origin API mounting.
func OriginCheck(allowedOrigins []string) func(http.Handler) http.Handler {
	allowAll := false
	origins := make(map[string]bool)
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
			break
		}
		origins[strings.TrimRight(o, "/")] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if allowAll {
				next.ServeHTTP(w, r)
				return
			}

			// Only check state-changing methods
			switch r.Method {
			case "POST", "PUT", "PATCH", "DELETE":
			default:
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")

			// No Origin/Referer — treat as same-origin (e.g. direct API call,
			// curl, same-site form). This is intentionally permissive; callers
			// that require absolute protection should set AllowedOrigins.
			if origin == "" && referer == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check Origin first (it's more reliable)
			if origin != "" {
				if isAllowed(origin, origins) {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Fall back to Referer
			if refURL, err := url.Parse(referer); err == nil && refURL.String() != "" {
				refOrigin := refURL.Scheme + "://" + refURL.Host
				if isAllowed(refOrigin, origins) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

func isAllowed(origin string, origins map[string]bool) bool {
	if origins["*"] {
		return true
	}
	origin = strings.TrimRight(origin, "/")
	if origins[origin] {
		return true
	}
	// also check without port (common Origin: "https://example.com" vs config "https://example.com:443")
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	withoutPort := u.Scheme + "://" + u.Hostname()
	if origins[withoutPort] {
		return true
	}
	withDefaultPort := u.Scheme + "://" + u.Hostname() + ":" + u.Port()
	if u.Port() == "" {
		if u.Scheme == "https" {
			withDefaultPort = u.Scheme + "://" + u.Hostname() + ":443"
		} else {
			withDefaultPort = u.Scheme + "://" + u.Hostname() + ":80"
		}
	}
	return origins[withDefaultPort]
}
