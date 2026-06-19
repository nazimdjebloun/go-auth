package ratelimit

import "time"

type Config struct {
	Enabled       bool
	Default       Rate
	Endpoints     map[string]Rate
	Store         Store
	DisabledPaths []string
	TrustedIPs    []string
}

type Rate struct {
	Requests int
	Window   time.Duration
}

type Store interface {
	Increment(key string, window time.Duration) (int, error)
	Reset(key string) error
}
