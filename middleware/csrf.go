package middleware

import (
	"log/slog"
	"net"
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
//
// trustedIPs is the list of IPs/CIDRs allowed to set forwarded headers — the
// same list the rate limiter uses (config.rateLimit.TrustedIPs). Forwarded
// headers (X-Forwarded-Proto, X-Forwarded-Host, Forwarded) are only honored
// when the immediate connecting peer (r.RemoteAddr) is in this list; otherwise
// the effective scheme/host fall back to r.TLS / r.Host as-is, so a spoofing
// client cannot influence the same-origin comparison.
func OriginCheck(allowedOrigins []string, allowMissing bool, trustedIPs []string, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
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
				// Debug: normal non-browser/strict-mode traffic, high volume, deliberately below default log level to avoid flooding — raise handler level to Debug to see these.
				logRejectedRequest(r, logger, slog.LevelDebug, "csrf rejected", "missing origin and referer")
				http.Error(w, "Forbidden - CSRF headers missing", http.StatusForbidden)
				return
			}

			// Check Origin first (it's more reliable)
			if origin != "" {
				if isAllowed(origin, origins) || isSameOrigin(origin, r, trustedIPs) {
					next.ServeHTTP(w, r)
					return
				}
				logRejectedRequest(r, logger, slog.LevelWarn, "csrf rejected", "origin not allowed", slog.String("origin", origin))
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			// Fall back to Referer
			if refURL, err := url.Parse(referer); err == nil && refURL.String() != "" {
				refOrigin := refURL.Scheme + "://" + refURL.Host
				if isAllowed(refOrigin, origins) || isSameOrigin(refOrigin, r, trustedIPs) {
					next.ServeHTTP(w, r)
					return
				}
			}

			logRejectedRequest(r, logger, slog.LevelWarn, "csrf rejected", "referer not allowed", slog.String("referer", referer))
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
}

// isSameOrigin checks whether the given origin matches the request's own Host,
// handling standard port inference. Forwarded headers (X-Forwarded-Proto,
// X-Forwarded-Host, Forwarded) are only honored when the immediate connecting
// peer is in trustedIPs; otherwise r.TLS and r.Host are used.
func isSameOrigin(origin string, r *http.Request, trustedIPs []string) bool {
	scheme, host := requestSchemeHost(r, trustedIPs)
	expected := scheme + "://" + host
	// Normalize and compare
	return normalizeOrigin(origin) == normalizeOrigin(expected)
}

// requestSchemeHost returns the effective scheme and host for the request.
//
// When r.TLS is non-nil the scheme is https and the host is r.Host — forwarded
// headers are never consulted for a direct TLS connection.
//
// When r.TLS is nil (typical behind a reverse proxy), forwarded headers
// (X-Forwarded-Proto / Forwarded / X-Forwarded-Host) are honored ONLY when the
// immediate connecting peer (r.RemoteAddr) is in trustedIPs. This is the same
// trust posture as the rate limiter, which honors IPAddressHeader only when
// TrustedIPs is configured: a client-supplied forwarded header is spoofable,
// so it must not influence the same-origin comparison unless the connection
// came from a proxy we trust to set it. If the peer is not trusted we fall
// back to scheme "http" and r.Host as-is; the same-origin check then simply
// won't match the public origin (the allowedOrigins list still applies, and an
// empty trusted list trusts nobody).
func requestSchemeHost(r *http.Request, trustedIPs []string) (scheme, host string) {
	scheme = "http"
	if r.TLS != nil {
		scheme = "https"
		host = r.Host
		return
	}

	if peerIsTrusted(r, trustedIPs) {
		// r.TLS is nil — this is typical behind reverse proxies (nginx, Cloudflare,
		// ALB, Caddy, Traefik). Check forwarded headers to recover the original
		// scheme and host. These headers are set by the trusted proxy.
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
		}
	}

	if host == "" {
		host = r.Host
	}

	return
}

// peerIsTrusted reports whether the immediate connecting peer of the request
// matches one of the trusted IPs/CIDRs. Entries without "/" are exact IP
// matches; entries with "/" are CIDRs. An empty list trusts nobody, so
// forwarded headers are ignored.
func peerIsTrusted(r *http.Request, trustedIPs []string) bool {
	if len(trustedIPs) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	peer := net.ParseIP(host)
	if peer == nil {
		return false
	}
	for _, entry := range trustedIPs {
		if strings.Contains(entry, "/") {
			_, cidr, err := net.ParseCIDR(entry)
			if err == nil && cidr.Contains(peer) {
				return true
			}
			continue
		}
		if ip := net.ParseIP(entry); ip != nil && ip.Equal(peer) {
			return true
		}
	}
	return false
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
