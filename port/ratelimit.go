package port

import "time"

type Rate struct {
	Requests int
	Window   time.Duration
}

type RateLimitConfig struct {
	Enabled       bool
	Default       Rate
	Endpoints     map[string]Rate
	Store         RateLimitStore
	DisabledPaths []string
	TrustedIPs    []string
}

type RateLimitStore interface {
	Increment(key string, window time.Duration) (int, error)
	Reset(key string) error
}
