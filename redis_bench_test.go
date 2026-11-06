package goauth

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/redis/go-redis/v9"
)

// BenchmarkRedisValidation records the cost of the SQL-authoritative cache on
// a deliberately fast local database. It is not a claim of a production gain.
func BenchmarkRedisValidation(b *testing.B) {
	for _, mode := range []string{"sql", "redis"} {
		b.Run(mode, func(b *testing.B) {
			a := benchAuth(b)
			if mode == "redis" {
				addr := os.Getenv("GOAUTH_REDIS_TEST_ADDR")
				if addr == "" {
					b.Skip("Redis benchmark not selected")
				}
				client := redis.NewClient(&redis.Options{Addr: addr, ContextTimeoutEnabled: true, MaxRetries: -1, ReadTimeout: time.Second, WriteTimeout: time.Second})
				b.Cleanup(func() { _ = client.Close() })
				cfg := a.cfg.clone()
				WithRedis(RedisConfig{Client: client, Prefix: "bench:" + uuid.NewString()})(&cfg)
				var err error
				a, err = New(&cfg)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(a.Close)
			}
			id := uuid.NewString()
			now := time.Now().UTC()
			if err := sqlstore.NewUserRepository(a.db).Create(b.Context(), &domain.User{ID: id, Email: id + "@example.test", Name: "Benchmark", Role: domain.RoleUser, IsVerified: true, CreatedAt: now, UpdatedAt: now}); err != nil {
				b.Fatal(err)
			}
			created, err := a.services.Session.Create(b.Context(), api.CreateSessionInput{UserID: id, UserAgent: "Redis benchmark"})
			if err != nil {
				b.Fatal(err)
			}
			if _, _, err = a.services.Session.ValidateWithUser(b.Context(), created.SessionToken); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, _, err = a.services.Session.ValidateWithUser(b.Context(), created.SessionToken); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
