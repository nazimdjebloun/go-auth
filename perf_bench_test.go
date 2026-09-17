package goauth

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/nazimdjebloun/go-auth/internal/schema"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// benchAuth builds a full Auth on a private in-memory SQLite database with a
// deliberately low bcrypt cost (4) so database work is visible next to
// hashing. Cost-12 hashing is measured separately in BenchmarkHashCost12.
func benchAuth(b *testing.B) *Auth {
	b.Helper()
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		b.Fatal(err)
	}
	schemaSQL, err := GetSchema("sqlite")
	if err != nil {
		b.Fatal(err)
	}
	for _, stmt := range schema.SplitSQL(schemaSQL) {
		if _, err := db.Exec(stmt); err != nil {
			b.Fatalf("migrate: %v", err)
		}
	}
	cfg, err := NewConfig(minimalOpts(
		WithBcryptCost(4),
		WithApp(AppConfig{
			Name: "bench", BaseURL: "https://example.com",
			Database: DatabaseConfig{Driver: DriverSQLite, DB: db},
		}),
	)...)
	if err != nil {
		b.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(a.Close)
	return a
}

func benchRegister(b *testing.B, a *Auth, i int) string {
	res, err := a.Register(context.Background(), RegisterInput{
		Email:    fmt.Sprintf("bench%d@example.com", i),
		Password: "V@lidPswd1",
		Name:     "Bench",
	})
	if err != nil {
		b.Fatal(err)
	}
	return res.SessionToken
}

// BenchmarkRegister measures the full register path: policy check, bcrypt
// hash (cost 4 here), user insert, session + refresh creation.
func BenchmarkRegister(b *testing.B) {
	a := benchAuth(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Register(ctx, RegisterInput{
			Email:    fmt.Sprintf("reg%d@example.com", i),
			Password: "V@lidPswd1",
			Name:     "Bench",
		}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLogin measures password verify + session creation per login.
func BenchmarkLogin(b *testing.B) {
	a := benchAuth(b)
	ctx := context.Background()
	const pwd = "V@lidPswd1"
	if _, err := a.Register(ctx, RegisterInput{
		Email: "login@example.com", Password: pwd, Name: "Bench",
	}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.Login(ctx, LoginInput{
			Email: "login@example.com", Password: pwd,
		}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValidateSession is the per-request hot path.
func BenchmarkValidateSession(b *testing.B) {
	a := benchAuth(b)
	token := benchRegister(b, a, 0)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := a.Services.Auth.ValidateSession(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRefreshSession measures token rotation: old refresh consumed,
// new session token + refresh written. Each iteration chains off the
// previous rotation, so the loop measures a realistic repeated-refresh
// session rather than re-using a consumed token.
func BenchmarkRefreshSession(b *testing.B) {
	a := benchAuth(b)
	ctx := context.Background()
	res, err := a.Register(ctx, RegisterInput{
		Email: "refresh@example.com", Password: "V@lidPswd1", Name: "Bench",
	})
	if err != nil {
		b.Fatal(err)
	}
	refresh := res.RefreshToken
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := a.Services.Session.RefreshSession(ctx, refresh)
		if err != nil {
			b.Fatal(err)
		}
		refresh = out.RefreshToken
	}
}

// BenchmarkRateLimitAllow isolates the in-memory limiter decision that runs
// in front of every route.
func BenchmarkRateLimitAllow(b *testing.B) {
	store := ratelimit.NewMemoryStore()
	rate := ratelimit.DefaultRateLimitConfig().Default
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.Allow(ctx, "bench-key", rate); err != nil {
			b.Fatal(err)
		}
	}
}
