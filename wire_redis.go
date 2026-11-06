package goauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/redisstore"
)

type redisWiring struct {
	sessions, tokens    *sqlstore.SnapshotCache
	rate, notifications *redisstore.Store
}

func buildRedis(ctx context.Context, cfg *Config, keys keyring.Keys) (redisWiring, error) {
	var out redisWiring
	r := cfg.redis
	if r == nil {
		return out, nil
	}
	ctx, cancel := context.WithTimeout(ctx, r.StartupTimeout)
	defer cancel()
	id := sha256.Sum256(keys.RedisCache)
	prefix := r.Prefix + ":" + hex.EncodeToString(id[:8])
	cache, err := redisstore.New(redisstore.Config{Client: r.Client, Prefix: prefix + ":snapshots", Key: keys.RedisNames, OperationTimeout: r.OperationTimeout, MaxSnapshotBytes: r.MaxSnapshotBytes})
	if err != nil {
		return out, err
	}
	if redisEnabled(r.Sessions) || redisEnabled(r.Tokens) {
		if err = cache.Check(ctx); err != nil {
			return out, fmt.Errorf("goauth: redis snapshot startup: %w", err)
		}
	}
	if redisEnabled(r.Sessions) {
		out.sessions, err = sqlstore.NewSnapshotCache(cache, keys.RedisCache, r.SessionCacheTTL, r.MaxSnapshotBytes)
		if err != nil {
			return out, err
		}
	}
	if redisEnabled(r.Tokens) {
		out.tokens, err = sqlstore.NewSnapshotCache(cache, keys.RedisCache, r.TokenCacheTTL, r.MaxSnapshotBytes)
		if err != nil {
			return out, err
		}
	}
	client := r.CounterClient
	if client == nil {
		client = r.Client
	}
	makeStore := func(purpose string) (*redisstore.Store, error) {
		s, err := redisstore.New(redisstore.Config{Client: client, Prefix: prefix + ":" + purpose, Key: keys.RedisNames, OperationTimeout: r.OperationTimeout, MaxSnapshotBytes: r.MaxSnapshotBytes})
		if err != nil {
			return nil, err
		}
		if err = s.Check(ctx); err != nil {
			return nil, fmt.Errorf("goauth: redis %s startup: %w", purpose, err)
		}
		return s, nil
	}
	if redisEnabled(r.RateLimits) && cfg.rateLimit.Enabled {
		out.rate, err = makeStore("rate")
		if err != nil {
			return out, err
		}
	}
	if redisEnabled(r.TwoFactorNotifications) {
		out.notifications, err = makeStore("notifications")
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

// RedisCacheStats reports aggregate disposable-cache activity.
type RedisCacheStats struct {
	Hits   uint64 `json:"hits"`
	Misses uint64 `json:"misses"`
	Errors uint64 `json:"errors"`
	Writes uint64 `json:"writes"`
}

// RedisStats reports enabled Redis cache/counter activity. Nil fields identify
// disabled capabilities. No credential or record identifiers are included.
type RedisStats struct {
	Sessions               *RedisCacheStats  `json:"sessions,omitempty"`
	Tokens                 *RedisCacheStats  `json:"tokens,omitempty"`
	RateLimits             *redisstore.Stats `json:"rateLimits,omitempty"`
	TwoFactorNotifications *redisstore.Stats `json:"twoFactorNotifications,omitempty"`
}

// RedisStats returns a concurrent-safe activity snapshot, including SQL fallbacks
// through cache misses/errors. It does not execute any Redis or SQL commands.
func (a *Auth) RedisStats() RedisStats {
	var out RedisStats
	stats := func(c *sqlstore.SnapshotCache) *RedisCacheStats {
		v := c.Stats()
		return &RedisCacheStats{Hits: v.Hits, Misses: v.Misses, Errors: v.Errors, Writes: v.Writes}
	}
	if a.redis.sessions != nil {
		out.Sessions = stats(a.redis.sessions)
	}
	if a.redis.tokens != nil {
		out.Tokens = stats(a.redis.tokens)
	}
	if a.redis.rate != nil {
		v := a.redis.rate.Stats()
		out.RateLimits = &v
	}
	if a.redis.notifications != nil {
		v := a.redis.notifications.Stats()
		out.TwoFactorNotifications = &v
	}
	return out
}
