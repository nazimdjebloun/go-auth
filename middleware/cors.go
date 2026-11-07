package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// CORSConfig extends the built-in browser policy. Entries are additive: empty
// slices keep the defaults, and required auth headers and methods stay enabled.
type CORSConfig struct {
	AllowedHeaders []string // additional request headers, e.g. Idempotency-Key
	ExposedHeaders []string // additional response headers readable by JavaScript
	AllowedMethods []string // additional case-sensitive HTTP methods
}

// Validate checks names before they are placed into CORS response headers.
// Wildcards and browser-forbidden methods are rejected. This does not check
// whether an application actually implements the named methods or headers.
func (c CORSConfig) Validate() error {
	var errs []error
	for _, field := range []struct {
		name   string
		values []string
	}{
		{name: "allowed_headers", values: c.AllowedHeaders},
		{name: "exposed_headers", values: c.ExposedHeaders},
		{name: "allowed_methods", values: c.AllowedMethods},
	} {
		for _, value := range field.values {
			if !corsToken(value) || value == "*" {
				errs = append(errs, fmt.Errorf("cors: %s contains invalid name %q; use explicit HTTP tokens", field.name, value))
				continue
			}
			if field.name == "allowed_methods" {
				switch strings.ToUpper(value) {
				case "CONNECT", "TRACE", "TRACK":
					errs = append(errs, fmt.Errorf("cors: allowed_methods contains browser-forbidden method %q", value))
				}
			}
		}
	}
	return errors.Join(errs...)
}

// corsToken implements the ASCII token grammar shared by HTTP field names and
// methods. Lists, whitespace and control characters are never valid names.
func corsToken(value string) bool {
	if value == "" {
		return false
	}
	for _, ch := range value {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			continue
		}
		if !strings.ContainsRune("!#$%&'*+-.^_`|~", ch) {
			return false
		}
	}
	return true
}

func corsNames(defaults []string, additions []string, headers bool) string {
	values := append([]string(nil), defaults...)
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if headers {
			value = strings.ToLower(value)
		}
		seen[value] = true
	}
	for _, value := range additions {
		key := value
		if headers {
			value = http.CanonicalHeaderKey(value)
			key = strings.ToLower(value)
		}
		if !seen[key] {
			seen[key] = true
			values = append(values, value)
		}
	}
	return strings.Join(values, ", ")
}

// CORS adds cross-origin response headers for allowed origins. Optional configs
// extend the defaults; header names are deduplicated without regard to case,
// while methods are case-sensitive. Invalid configs panic during construction.
// Preflight exits before the next handler. Actual requests still require their
// normal authentication, authorization, and CSRF checks.
func CORS(allowedOrigins []string, configs ...CORSConfig) func(http.Handler) http.Handler {
	var cfg CORSConfig
	for _, extra := range configs {
		if err := extra.Validate(); err != nil {
			panic(err)
		}
		cfg.AllowedHeaders = append(cfg.AllowedHeaders, extra.AllowedHeaders...)
		cfg.ExposedHeaders = append(cfg.ExposedHeaders, extra.ExposedHeaders...)
		cfg.AllowedMethods = append(cfg.AllowedMethods, extra.AllowedMethods...)
	}
	allowedHeaders := corsNames(
		[]string{"Content-Type", "Authorization", "X-CSRF-Token", "X-GoAuth-Session", "If-Match"},
		cfg.AllowedHeaders, true,
	)
	exposedHeaders := corsNames([]string{"X-CSRF-Token", "Retry-After"}, cfg.ExposedHeaders, true)
	allowedMethods := corsNames([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, cfg.AllowedMethods, false)
	allowAll := false
	origins := make(map[string]bool)
	for _, o := range allowedOrigins {
		if o == "*" {
			allowAll = true
			break
		}
		origins[o] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if origin != "" && (allowAll || origins[origin]) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
				w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
				w.Header().Set("Access-Control-Expose-Headers", exposedHeaders)
				// The origin is echoed verbatim, so the response varies by the
				// Origin header; without this, a shared cache could serve one
				// origin's response to another.
				w.Header().Add("Vary", "Origin")
				// Credentials are only granted for a specific configured
				// origin. Echoing the request origin with Allow-Credentials
				// under a wildcard config would let any site read
				// authenticated responses.
				if origins[origin] {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
