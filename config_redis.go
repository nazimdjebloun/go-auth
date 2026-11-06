package goauth

import (
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/redisstore"
	"github.com/redis/go-redis/v9"
)

// RedisConfig enables SQL-authoritative session/token snapshots and distributed
// counters. Clients are caller-owned and must honor context deadlines. Nil
// capability pointers enable that capability; false explicitly disables it.
type RedisConfig struct {
	Client                 redis.UniversalClient
	CounterClient          redis.UniversalClient
	Prefix                 string
	Sessions               *bool
	Tokens                 *bool
	RateLimits             *bool
	TwoFactorNotifications *bool
	OperationTimeout       time.Duration
	StartupTimeout         time.Duration
	SessionCacheTTL        time.Duration
	TokenCacheTTL          time.Duration
	MaxSnapshotBytes       int
}

func redisEnabled(v *bool) bool { return v == nil || *v }

func cloneRedis(in *RedisConfig) *RedisConfig {
	if in == nil {
		return nil
	}
	out := *in
	clone := func(v *bool) *bool {
		if v == nil {
			return nil
		}
		x := *v
		return &x
	}
	out.Sessions = clone(in.Sessions)
	out.Tokens = clone(in.Tokens)
	out.RateLimits = clone(in.RateLimits)
	out.TwoFactorNotifications = clone(in.TwoFactorNotifications)
	return &out
}

// WithRedis configures all Redis capabilities by default. SQL remains the
// authority for credentials and transactions, including when Redis is down.
func WithRedis(cfg RedisConfig) Option { return func(c *Config) { c.redis = cloneRedis(&cfg) } }

func (c *Config) applyRedisDefaults() {
	r := c.redis
	if r == nil {
		return
	}
	if r.Prefix == "" {
		r.Prefix = "goauth:v1"
	}
	if r.OperationTimeout == 0 {
		r.OperationTimeout = 250 * time.Millisecond
	}
	if r.StartupTimeout == 0 {
		r.StartupTimeout = 5 * time.Second
	}
	if r.SessionCacheTTL == 0 {
		r.SessionCacheTTL = 5 * time.Minute
	}
	if r.TokenCacheTTL == 0 {
		r.TokenCacheTTL = time.Minute
	}
	if r.MaxSnapshotBytes == 0 {
		r.MaxSnapshotBytes = 256 * 1024
	}
}

func (c *Config) validateRedis() []error {
	r := c.redis
	if r == nil {
		return nil
	}
	var errs []error
	if len(r.Prefix) > 110 {
		errs = append(errs, fmt.Errorf("redis: prefix must not exceed 110 bytes"))
	}
	if _, err := redisstore.New(redisstore.Config{Client: r.Client, Prefix: r.Prefix, OperationTimeout: r.OperationTimeout, MaxSnapshotBytes: r.MaxSnapshotBytes}); err != nil {
		errs = append(errs, fmt.Errorf("redis: %w", err))
	}
	if r.CounterClient != nil {
		if _, err := redisstore.New(redisstore.Config{Client: r.CounterClient, Prefix: r.Prefix, OperationTimeout: r.OperationTimeout, MaxSnapshotBytes: r.MaxSnapshotBytes}); err != nil {
			errs = append(errs, fmt.Errorf("redis counters: %w", err))
		}
	}
	if r.StartupTimeout <= 0 || r.SessionCacheTTL <= 0 || r.TokenCacheTTL <= 0 {
		errs = append(errs, fmt.Errorf("redis: startup timeout and cache ttls must be positive"))
	}
	if redisEnabled(r.RateLimits) && c.rateLimit != nil && c.rateLimit.Enabled && c.set.rateLimitStore {
		errs = append(errs, fmt.Errorf("redis: rate limits conflict with a supplied rate-limit store; disable Redis RateLimits explicitly"))
	}
	return errs
}
