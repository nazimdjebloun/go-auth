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
// are still permitted.
// If allowMissing is false, requests without Origin and Referer are rejected.
func OriginCheck(allowedOrigins []string, allowMissing bool) func(http.Handler) http.Handler {
	allowAll := false
	origins := make(map[string]bool)
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
			break
		}
		if o == "" {
			continue
		}
		origins[normalizeOrigin(o)] = true
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

			// No Origin/Referer
			if origin == "" && referer == "" {
				if allowMissing {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "Forbidden - CSRF headers missing", http.StatusForbidden)
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
// handling standard port inference. When behind a reverse proxy (r.TLS is nil
// but X-Forwarded-Proto is set), the forwarded headers are used to determine
// the original scheme and host.
func isSameOrigin(origin string, r *http.Request) bool {
	scheme, host := requestSchemeHost(r)
	expected := scheme + "://" + host
	// Normalize and compare
	return normalizeOrigin(origin) == normalizeOrigin(expected)
}

// requestSchemeHost returns the effective scheme and host for the request,
// respecting reverse proxy forwarded headers when the direct connection
// appears to be plaintext (r.TLS == nil).
func requestSchemeHost(r *http.Request) (scheme, host string) {
	scheme = "http"
	if r.TLS != nil {
		scheme = "https"
		host = r.Host
		return
	}

	// r.TLS is nil — this is typical behind reverse proxies (nginx, Cloudflare,
	// ALB, Caddy, Traefik). Check forwarded headers to recover the original
	// scheme and host. These headers are set by the proxy and should not be
	// trusted from arbitrary clients, but for same-origin CSRF checks the
	// worst case is an attacker making CSRF work for themselves (not exploitable).
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		if p := strings.SplitN(proto, ",", 2)[0]; p == "https" || p == "http" {
			scheme = p
		}
	} else if forwarded := r.Header.Get("Forwarded"); forwarded != "" {
		// RFC 7239: Forwarded: for=192.0.2.60;proto=https;host=example.com
		for _, part := range strings.Split(forwarded, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "proto=") {
				proto := strings.TrimSpace(part[6:])
				if proto == "https" || proto == "http" {
					scheme = proto
					break
				}
			}
		}
	}

	// For Host, check X-Forwarded-Host first (proxy may have multiple virtual hosts).
	if xhost := r.Header.Get("X-Forwarded-Host"); xhost != "" {
		host = strings.TrimSpace(strings.SplitN(xhost, ",", 2)[0])
	} else {
		host = r.Host
	}

	return
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
