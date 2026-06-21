package middleware

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func extractIP(r *http.Request, cfg *ratelimit.Config) string {
	ip := ""
	if cfg.IPAddressHeader != "" {
		ip = r.Header.Get(cfg.IPAddressHeader)
	}
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
	}
	if ip == "" {
		ip = r.Header.Get("X-Real-IP")
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

func RateLimit(cfg *ratelimit.Config) func(http.Handler) http.Handler {
	if cfg == nil || !cfg.Enabled {
		return func(next http.Handler) http.Handler { return next }
	}

	var store ratelimit.Store
	if cfg.Store != nil {
		store = cfg.Store
	} else {
		store = ratelimit.NewMemoryStore()
	}

	trusted := make(map[string]bool)
	for _, ip := range cfg.TrustedIPs {
		trusted[ip] = true
	}

	disabled := make(map[string]bool)
	for _, path := range cfg.DisabledPaths {
		disabled[path] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := extractIP(r, cfg)

			if trusted[clientIP] {
				next.ServeHTTP(w, r)
				return
			}

			if disabled[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			routeKey := r.Method + " " + r.URL.Path
			rate, ok := cfg.Routes[routeKey]
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
				log.Printf("rate limit error: %v", err)
				next.ServeHTTP(w, r)
				return
			}

			if result.Count > rate.Requests {
				w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rate.Requests))
				w.Header().Set("X-RateLimit-Remaining", "0")
				w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(result.ResetAt).Seconds())))
				writeJSON(w, http.StatusTooManyRequests, map[string]string{
					"error":   "rate_limit_exceeded",
					"message": "Too many requests, please try again later",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
