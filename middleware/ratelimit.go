package middleware

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func extractIP(r *http.Request, cfg *ratelimit.Config) string {
	ip := ""
	// Only honor the IPAddressHeader when the immediate peer is a trusted
	// proxy (the same list the CSRF origin check uses). An untrusted client
	// can otherwise spoof the header to pick the rate-limit key.
	if peerIsTrusted(r, cfg.TrustedIPs) {
		ip = r.Header.Get(cfg.IPAddressHeader)
	}
	if ip == "" {
		ip = r.RemoteAddr
	}

	if idx := strings.Index(ip, ","); idx != -1 {
		ip = strings.TrimSpace(ip[:idx])
	}

	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	parsed := net.ParseIP(ip)
	if parsed != nil && parsed.To4() == nil {
		subnet := cfg.IPv6Subnet
		if subnet <= 0 {
			subnet = 64
		}
		mask := net.CIDRMask(subnet, 128)
		ip = parsed.Mask(mask).String()
	}

	return ip
}

func rateLimitKey(r *http.Request, ip string) string {
	return fmt.Sprintf("%s %s:%s", r.Method, r.URL.Path, ip)
}

// matchWildcardRoute finds the Routes entry matching routeKey ("METHOD
// /path") where the pattern has "*" wildcard segments (from
// routes.Glob — one wildcard per ServeMux path parameter). A pattern
// matches only when it has the same number of segments as routeKey, with
// each non-"*" segment equal. When more than one pattern matches — not
// expected of the built-in table, since it has one entry per route, but
// possible in a caller-supplied Routes map — the one with the fewest
// wildcard segments (the most specific) wins.
func matchWildcardRoute(routesMap map[string]ratelimit.Rate, routeKey string) (ratelimit.Rate, bool) {
	reqSegs := strings.Split(routeKey, "/")

	var best ratelimit.Rate
	found := false
	bestWildcards := -1

	for pattern, rate := range routesMap {
		if !strings.Contains(pattern, "*") {
			continue
		}
		patSegs := strings.Split(pattern, "/")
		if len(patSegs) != len(reqSegs) {
			continue
		}
		wildcards := 0
		matched := true
		for i, seg := range patSegs {
			if seg == "*" {
				wildcards++
				continue
			}
			if seg != reqSegs[i] {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		if !found || wildcards < bestWildcards {
			best = rate
			bestWildcards = wildcards
			found = true
		}
	}

	return best, found
}

func RateLimit(cfg *ratelimit.Config) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	var store ratelimit.Store
	if cfg.Store != nil {
		store = cfg.Store
	} else {
		store = ratelimit.NewMemoryStore()
	}

	disabled := make(map[string]bool)
	for _, path := range cfg.DisabledPaths {
		disabled[path] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := extractIP(r, cfg)

			if disabled[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			routeKey := r.Method + " " + r.URL.Path
			rate, ok := cfg.Routes[routeKey]
			if !ok {
				rate, ok = matchWildcardRoute(cfg.Routes, routeKey)
			}
			if !ok {
				rate = cfg.Default
			}

			if rate.Requests <= 0 {
				next.ServeHTTP(w, r)
				return
			}

			storeKey := rateLimitKey(r, clientIP)
			result, err := store.Increment(storeKey, rate.Window)
			if err != nil {
				cfg.Logger.Error("rate limit store error",
					"error", err,
					"method", r.Method,
					"path", r.URL.Path,
					"ip", clientIP,
				)
				w.Header().Set("Retry-After", "60")
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"error":   "rate_limit_error",
					"message": "Service temporarily unavailable",
				}, cfg.Logger)
				return
			}

			if result.Count > rate.Requests {
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rate.Requests))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(result.ResetAt).Seconds())))
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"error":   "rate_limit_exceeded",
					"message": "Too many requests, please try again later",
				}, cfg.Logger)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
