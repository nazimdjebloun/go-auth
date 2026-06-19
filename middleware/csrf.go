package middleware

import (
	"net/http"
	"net/url"
	"strings"
)

// OriginCheck returns middleware that validates Origin or Referer headers on
// state-changing requests (POST, PUT, PATCH, DELETE) to defend against CSRF.
// When allowedOrigins contains "*" the check is skipped.
// When allowedOrigins is empty, same-origin requests (Origin matching r.Host)
// are still permitted — you can configure AllowedOrigins for stricter control.
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

			// No Origin/Referer — treat as same-origin (e.g. direct API call, curl).
			if origin == "" && referer == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check Origin first (it's more reliable)
			if origin != "" {
				if isAllowed(origin, origins) || isSameOrigin(origin, r) {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Fall back to Referer
			if refURL, err := url.Parse(referer); err == nil && refURL.String() != "" {
				refOrigin := refURL.Scheme + "://" + refURL.Host
				if isAllowed(refOrigin, origins) || isSameOrigin(refOrigin, r) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

// isSameOrigin checks whether the given origin matches the request's own Host,
// handling standard port inference.
func isSameOrigin(origin string, r *http.Request) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	expected := scheme + "://" + r.Host
	// Normalize and compare
	return normalizeOrigin(origin) == normalizeOrigin(expected)
}

func normalizeOrigin(origin string) string {
	origin = strings.TrimRight(origin, "/")
	u, err := url.Parse(origin)
	if err != nil {
		return origin
	}
	if u.Port() == "" {
		if u.Scheme == "https" {
			return u.Scheme + "://" + u.Hostname() + ":443"
		}
		return u.Scheme + "://" + u.Hostname() + ":80"
	}
	return u.Scheme + "://" + u.Hostname() + ":" + u.Port()
}

func isAllowed(origin string, origins map[string]bool) bool {
	if origins["*"] {
		return true
	}
	return origins[normalizeOrigin(origin)]
}
