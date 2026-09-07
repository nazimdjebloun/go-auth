package middleware

import (
	"net"
	"net/http"
	"strings"
)

// ClientIPConfig says how far to trust a forwarding header when working out
// where a request actually came from. Both fields mirror the rate limiter's
// (ratelimit.Config.IPAddressHeader / TrustedIPs) so one deployment's proxy
// setup is described once and every subsystem agrees about it.
type ClientIPConfig struct {
	// Header is the forwarding header to read, e.g. "X-Forwarded-For" or
	// "CF-Connecting-IP". Empty means never read one.
	Header string
	// TrustedIPs are the IPs/CIDRs allowed to supply Header. An empty list
	// trusts nobody, so Header is ignored — a client-supplied header is
	// spoofable, and an unverified one is worse than no header at all.
	TrustedIPs []string
}

// ClientIP resolves the address a request came from, for recording on a
// session or an audit event.
//
// Behind a reverse proxy r.RemoteAddr is the proxy, so every session would
// otherwise be stamped with the proxy's address — and the session list and
// audit log, whose entire purpose is to show an operator where a login came
// from, would show the same loopback address for every user.
//
// The header is honored only when the immediate peer is in TrustedIPs, and
// then the *rightmost* hop that isn't itself a trusted proxy is taken: with
// an appending chain (nginx's proxy_add_x_forwarded_for, and every CDN) the
// entries to the right were written by infrastructure we trust, while the
// entries to the left are whatever the client sent. A client that opens with
// "X-Forwarded-For: 1.2.3.4" prepends a hop of its own choosing, so reading
// leftmost lets it write its own audit trail.
//
// The result is always a parsed IP or r.RemoteAddr's host — never a value
// copied verbatim out of a header. Unlike the rate limiter's key, IPv6 is
// not masked to a subnet: this is a record of who connected, not a bucket to
// group them into, so the exact address is the point.
func ClientIP(r *http.Request, cfg ClientIPConfig) string {
	if cfg.Header != "" && peerIsTrusted(r, cfg.TrustedIPs) {
		if hop := selectForwardedIP(r.Header.Values(cfg.Header), cfg.TrustedIPs); hop != "" {
			if ip := parseIPExact(hop); ip != "" {
				return ip
			}
			// Header present but unparseable: fall through to the transport
			// address rather than trusting what we were handed.
		}
	}
	if ip := parseIPExact(r.RemoteAddr); ip != "" {
		return ip
	}
	// Not an address at all. RemoteAddr is set by net/http and normally
	// parses; httptest and unix sockets are the realistic exceptions, and a
	// caller is better served by the raw value than by an empty string.
	return stripPort(r.RemoteAddr)
}

// parseIPExact returns raw's canonical IP form, with any port and brackets
// removed, or "" when raw is not an IP address. No IPv6 masking — see
// ClientIP.
func parseIPExact(raw string) string {
	raw = stripPort(strings.TrimSpace(raw))
	parsed := net.ParseIP(raw)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.String()
}

func stripPort(raw string) string {
	raw = strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	return strings.Trim(raw, "[]")
}
