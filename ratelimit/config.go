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
			// Login / register (including aliases mounted by Auth.Mount)
			"POST /auth/login":    {Requests: 5, Window: time.Minute},
			"POST /auth/signin":   {Requests: 5, Window: time.Minute},
			"POST /auth/register": {Requests: 3, Window: time.Minute},
			"POST /auth/signup":   {Requests: 3, Window: time.Minute},
			// Password / verification
			"POST /auth/forgot-password":        {Requests: 3, Window: time.Hour},
			"POST /auth/reset-password":         {Requests: 5, Window: time.Minute},
			"POST /auth/verify-email":           {Requests: 10, Window: time.Minute},
			"POST /auth/verify-email/resend":    {Requests: 3, Window: time.Minute},
			"POST /auth/resend-verification":    {Requests: 3, Window: time.Minute},
			"POST /auth/set-password/request":   {Requests: 3, Window: 15 * time.Minute},
			"POST /auth/set-password/confirm":   {Requests: 5, Window: 10 * time.Minute},
			"POST /auth/account/delete/request": {Requests: 3, Window: time.Hour},
			"POST /auth/account/delete/confirm": {Requests: 3, Window: time.Hour},
			// Invites / refresh
			"POST /auth/invite/register": {Requests: 10, Window: time.Minute},
			"POST /auth/refresh":         {Requests: 3, Window: time.Minute},
		},
	}
}
