package ratelimit

import "time"

type StoreResult struct {
	Count   int
	ResetAt time.Time
}

type Store interface {
	Increment(key string, window time.Duration) (StoreResult, error)
	Reset(key string) error
}

type Config struct {
	Enabled         bool
	Default         Rate
	Routes          map[string]Rate
	Store           Store
	DisabledPaths   []string
	TrustedIPs      []string
	IPv6Subnet      int    // subnet prefix length for IPv6 rate limiting (default 64)
	IPAddressHeader string // e.g. "CF-Connecting-IP", "X-Real-IP" (default: "X-Forwarded-For")
}

type Rate struct {
	Requests int
	Window   time.Duration
}

func DefaultRateLimitConfig() *Config {
	return &Config{
		Enabled:    false, // must be explicitly enabled — avoids blocking dev workflows
		IPv6Subnet: 64,
		Default:    Rate{Requests: 60, Window: time.Minute},
		Store:      NewMemoryStore(),
		Routes: map[string]Rate{
			"POST /auth/login":           {Requests: 5, Window: time.Minute},
			"POST /auth/register":        {Requests: 3, Window: time.Minute},
			"POST /auth/forgot-password": {Requests: 3, Window: time.Hour},
			"POST /auth/verify-email":    {Requests: 10, Window: time.Minute},
			"POST /auth/reset-password":  {Requests: 5, Window: time.Minute},
			"POST /auth/invite":          {Requests: 10, Window: time.Minute},
		},
	}
}
