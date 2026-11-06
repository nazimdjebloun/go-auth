package goauth

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/redis/go-redis/v9"
)

func TestRedisConfigClonesIntentAndRejectsConflict(t *testing.T) {
	c := redis.NewClient(&redis.Options{Addr: "unused:1", ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = c.Close() })
	no := false
	cfg, e := NewConfig(minimalOpts(WithRedis(RedisConfig{Client: c, Sessions: &no}))...)
	if e != nil {
		t.Fatal(e)
	}
	no = true
	if redisEnabled(cfg.redis.Sessions) {
		t.Fatal("configuration shares caller boolean")
	}
	clone := cfg.clone()
	*clone.redis.Sessions = true
	if redisEnabled(cfg.redis.Sessions) {
		t.Fatal("clone shares intent")
	}
	store := ratelimit.NewMemoryStore()
	defer store.(ratelimit.StoreCloser).Close()
	if _, e = NewConfig(minimalOpts(WithRedis(RedisConfig{Client: c}), WithRateLimitStore(store))...); e == nil {
		t.Fatal("conflicting stores accepted")
	}
}

func TestRedisAuthIntegration(t *testing.T) {
	addr := os.Getenv("GOAUTH_REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("GOAUTH_REDIS_TEST_ADDR not selected")
	}
	c := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1, ContextTimeoutEnabled: true, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second})
	t.Cleanup(func() { _ = c.Close() })
	a := buildAuth(t, minimalOpts(WithRedis(RedisConfig{Client: c, Prefix: "goauth-auth-test:" + uuid.NewString()}), WithPasswordHashing(PasswordHashingConfig{BcryptCost: 4}))...)
	t.Cleanup(a.Close)
	result, e := a.Register(t.Context(), api.RegisterInput{Email: uuid.NewString() + "@example.test", Password: "RedisTest1!", Name: "Redis test"})
	if e != nil {
		t.Fatal(e)
	}
	if result.SessionToken == "" {
		t.Fatal("registration returned no session")
	}
	for range 2 {
		if _, _, e = a.services.Session.ValidateWithUser(t.Context(), result.SessionToken); e != nil {
			t.Fatal(e)
		}
	}
	stats := a.RedisStats()
	if stats.Sessions == nil || stats.Sessions.Hits == 0 || stats.Tokens == nil || stats.RateLimits == nil || stats.TwoFactorNotifications == nil {
		t.Fatalf("incomplete Redis wiring: %+v", stats)
	}
	if e = a.services.Session.Revoke(t.Context(), result.SessionToken); e != nil {
		t.Fatal(e)
	}
	if _, _, e = a.services.Session.ValidateWithUser(t.Context(), result.SessionToken); e == nil {
		t.Fatal("cached session survived revocation")
	}
	a.Close()
	if e = c.Ping(t.Context()).Err(); e != nil {
		t.Fatal("Auth.Close closed caller Redis", e)
	}
}
