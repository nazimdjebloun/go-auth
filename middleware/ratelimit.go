package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/ratelimitpolicy"
	"github.com/nazimdjebloun/go-auth/internal/routepattern"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// maxKeyPattern bounds the pattern half of a key. Every source of a pattern
// is configuration or router metadata today, so nothing can drive this — it
// is here so "a rate-limit key is bounded" stays true by construction rather
// than by auditing every caller of RateLimitWithPattern.
const maxKeyPattern = 256

// unknownIP is the key material for a peer whose address won't parse. The
// raw value is never used: RemoteAddr is set by net/http and is safe, but
// the forwarding header is attacker-supplied when a trusted proxy passes it
// through unvalidated, and returning it verbatim would put arbitrary
// client-chosen bytes into the map key — the same unbounded-key-space
// problem as keying on the raw path, reached by a different door.
const unknownIP = "unknown"

// extractIP resolves the client address a limit is charged to. The result is
// always either a parsed, normalized IP or the unknownIP constant — never a
// value copied out of a request header.
func extractIP(r *http.Request, cfg *ratelimit.Config) string {
	raw := ""
	// Only honor the IPAddressHeader when the immediate peer is a trusted
	// proxy (the same list the CSRF origin check uses). An untrusted client
	// can otherwise spoof the header to pick the rate-limit key.
	if cfg.IPAddressHeader != "" && peerIsTrusted(r, cfg.TrustedIPs) {
		raw = selectForwardedIP(r.Header.Values(cfg.IPAddressHeader), cfg.TrustedIPs)
	}
	if raw == "" {
		raw = r.RemoteAddr
	}

	if ip := normalizeIP(raw, cfg.IPv6Subnet); ip != "" {
		return ip
	}
	// The header was present but unparseable. Fall back to the transport
	// address rather than trusting what we were handed.
	if ip := normalizeIP(r.RemoteAddr, cfg.IPv6Subnet); ip != "" {
		return ip
	}
	return unknownIP
}

// selectForwardedIP picks the client address out of a forwarding header,
// taking the rightmost hop that isn't itself a trusted proxy.
//
// Rightmost, not leftmost. With an appending proxy chain (nginx's
// proxy_add_x_forwarded_for, and every CDN), each hop appends the address it
// saw, so the entries to the right were written by infrastructure we trust
// and the entries to the left are whatever the client sent — a client that
// opens with "X-Forwarded-For: <anything>" prepends a hop of its own
// choosing. Reading leftmost hands the client its own rate-limit key, which
// is both a bypass (rotate the value, never hit a limit) and an unbounded
// key space.
func selectForwardedIP(values []string, trusted []string) string {
	var hops []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				hops = append(hops, part)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		if !ipIsTrusted(hops[i], trusted) {
			return hops[i]
		}
	}
	// Every hop is a trusted proxy: nothing in the header identifies a
	// client, so the caller falls back to RemoteAddr.
	return ""
}

// normalizeIP parses raw (with or without a port, with or without brackets)
// and returns its canonical key form, masking IPv6 to subnet bits. It
// returns "" when raw is not an IP address at all.
//
// The IPv6 mask is why a client with a routed /64 can't rotate addresses to
// get a fresh counter per request. It is also why the default of 64 is worth
// revisiting in a hostile environment: a /48 allocation is 65,536 distinct
// /64s from a single host.
func normalizeIP(raw string, subnet int) string {
	raw = strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	raw = strings.Trim(raw, "[]")

	parsed := net.ParseIP(raw)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	if subnet <= 0 || subnet > 128 {
		subnet = 64
	}
	return parsed.Mask(net.CIDRMask(subnet, 128)).String()
}

// rateLimitKey builds the counter key from the *pattern* a request matched,
// never its raw path.
//
// Keying on r.URL.Path is what made this store unbounded. Most of the
// rate-limited routes carry a path parameter — POST /auth/orgs/{orgID}/invites
// among them — so a caller who varies that segment mints a fresh counter on
// every request: the limit never trips, because no key ever repeats, and the
// map grows for as long as the requests keep coming. Keying on the pattern
// collapses all of those onto one counter per client, which is what the
// configured limit was always meant to mean.
func rateLimitKey(method, pattern, ip string) string {
	if len(pattern) > maxKeyPattern {
		sum := sha256.Sum256([]byte(pattern))
		pattern = pattern[:maxKeyPattern] + "#" + hex.EncodeToString(sum[:8])
	}
	return normalizeMethod(method) + " " + pattern + ":" + ip
}

// otherMethod is the key material for any method outside the standard set.
const otherMethod = "OTHER"

// normalizeMethod folds the request method down to a fixed set before it
// becomes key material.
//
// r.Method is request-line input and net/http does not bound it: the server
// checks that every byte is an HTTP token, not how many there are, so a
// ~1 MB method is accepted and handed to the handler verbatim (verified
// against net/http, not inferred). Concatenated into a key, that turns the
// store's entry cap into no cap at all — 100,000 entries is a memory bound
// only if entries are a bounded size, and 100,000 × 1 MB is not.
//
// The route's own patterns are already bounded, so this is the last piece of
// the key an attacker could size. Capping the length wouldn't be enough on
// its own: 100,000 distinct short methods would still be 100,000 distinct
// counters. Folding to a fixed set bounds both the size of a key and how
// many keys the method can produce.
//
// The method is in the key at all so GET /x and DELETE /x don't share a
// counter. Nine methods cover that; a tenth has no legitimate claim to its
// own budget, and anything non-standard sharing the OTHER bucket per client
// is a tighter limit, not a looser one.
func normalizeMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodConnect,
		http.MethodOptions, http.MethodTrace:
		return method
	default:
		return otherMethod
	}
}

// RateLimit returns rate-limiting middleware for the given configuration.
func RateLimit(cfg *ratelimit.Config) func(http.Handler) http.Handler {
	return rateLimit(cfg, "")
}

// RateLimitWithPattern is RateLimit for a handler mounted on a router that
// doesn't populate http.Request.Pattern — chi, gorilla/mux, echo, and
// anything else that isn't net/http's ServeMux.
//
// Pass the canonical ServeMux pattern, for example "POST /widgets/{id}/publish".
// It is validated during construction; malformed patterns panic like ServeMux
// registration. Requests that do not match the declaration receive 404.
// The rate table uses the same syntax and selects both rate and counter key.
func RateLimitWithPattern(cfg *ratelimit.Config, pattern string) func(http.Handler) http.Handler {
	if pattern == "" {
		panic("rate limit: declared route pattern must not be empty")
	}
	return rateLimit(cfg, pattern)
}

func rateLimit(cfg *ratelimit.Config, declared string) func(http.Handler) http.Handler {
	var declaration *routepattern.Matcher[bool]
	if declared != "" {
		var err error
		declaration, err = routepattern.New(map[string]bool{declared: true})
		if err != nil {
			panic(err)
		}
	}
	guard := func(next http.Handler) http.Handler {
		if declaration == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, _, ok := declaration.Match(r); !ok {
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	if cfg == nil || !cfg.Enabled {
		return guard
	}
	policy, err := ratelimitpolicy.New(cfg)
	if err != nil {
		panic(err)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	// Fill in the store on the Config rather than in a local, so every
	// middleware built from this Config shares one — and so Auth.Close,
	// which closes cfg.Store, can reach it. A local here meant a store
	// (and its cleanup goroutine) that nothing else could ever see or stop.
	// Safe without synchronization: middleware is constructed during wiring,
	// before any request is served.
	if cfg.Store == nil {
		cfg.Store = ratelimit.NewMemoryStore(ratelimit.WithStoreLogger(cfg.Logger))
	}
	store := cfg.Store

	return func(next http.Handler) http.Handler {
		return guard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rate, pattern := policy.Match(r, cfg.Default, declared)
			if rate.Requests <= 0 {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := extractIP(r, cfg)
			result, err := store.Allow(r.Context(), rateLimitKey(r.Method, pattern, clientIP), rate)
			if err != nil {
				if r.Context().Err() != nil {
					return
				}
				// Both fields are request-line input and neither is bounded
				// by net/http (the method isn't length-checked at all).
				// This line fires per request while a store is down, so
				// logging them raw would turn a backend outage into a
				// log-volume incident.
				cfg.Logger.Error("rate limit store error",
					"error", err,
					"method", normalizeMethod(r.Method),
					"path", truncateForLog(r.URL.Path),
					"ip", clientIP,
				)
				w.Header().Set("Retry-After", "60")
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"error":   "rate_limit_error",
					"message": "Service temporarily unavailable",
				}, cfg.Logger)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rate.Requests))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(result.Remaining))

			if !result.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(result.ResetAt)))
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"error":   "rate_limit_exceeded",
					"message": "Too many requests, please try again later",
				}, cfg.Logger)
				return
			}

			next.ServeHTTP(w, r)
		}))
	}
}

// truncateForLog caps an untrusted string at maxKeyPattern bytes, marking
// what it cut so a truncated value can't be mistaken for a short one.
func truncateForLog(s string) string {
	if len(s) <= maxKeyPattern {
		return s
	}
	return s[:maxKeyPattern] + "…(truncated)"
}

// retryAfterSeconds rounds up and clamps to at least 1. Truncating toward
// zero produced "Retry-After: 0" for any window with under a second left —
// an instruction to retry immediately, straight back into the limit — and a
// negative value for a reset that had just passed.
func retryAfterSeconds(resetAt time.Time) int {
	secs := int(math.Ceil(time.Until(resetAt).Seconds()))
	if secs < 1 {
		return 1
	}
	return secs
}
