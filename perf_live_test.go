package goauth

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// BenchmarkHashCost12 reports the default production password-hash cost in
// isolation, so the cost-4 service benchmarks above can be read against the
// hashing floor a real deployment pays per register/login.
func BenchmarkHashCost12(b *testing.B) {
	password := []byte(validTestPassword())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := bcrypt.GenerateFromPassword(password, 12); err != nil {
			b.Fatal(err)
		}
	}
}

// liveBenchAuth opens a URL-backed Auth against a live database server.
// Skipped unless the driver's DSN environment variable is set; uses the
// same URL path production uses, so the pool budget is in effect.
//
// Benchmarks write rows (users, sessions, refresh tokens) into the target
// database and cannot clean them up reliably across crash-killed runs —
// point the DSN at a disposable database.
func liveBenchAuth(b *testing.B, driver Driver, envVar string) *Auth {
	dsn := os.Getenv(envVar)
	if dsn == "" {
		b.Skipf("%s not set — live %s benchmarks skipped", envVar, driver)
	}
	cfg, err := NewConfig(minimalOpts(
		WithBcryptCost(4),
		WithApp(AppConfig{
			Name: "bench", BaseURL: "https://example.com",
			Database: DatabaseConfig{URL: dsn, Driver: driver, MaxOpenConns: 8},
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

// BenchmarkLivePostgres_ValidateSession exercises session validation
// against a real PostgreSQL server. Set GOAUTH_POSTGRES_TEST_DSN.
// The database must already have the schema applied (goauth migrate).
func BenchmarkLivePostgres_ValidateSession(b *testing.B) {
	a := liveBenchAuth(b, DriverPostgres, "GOAUTH_POSTGRES_TEST_DSN")
	res, err := a.Register(context.Background(), RegisterInput{
		Email:    fmt.Sprintf("pgbench-v-%d@example.com", time.Now().UnixNano()),
		Password: validTestPassword(),
		Name:     "Bench",
	})
	if err != nil {
		b.Fatal(err)
	}
	token := res.SessionToken
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := a.Services.Auth.ValidateSession(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLivePostgres_RefreshSession chains rotations against a live
// PostgreSQL server. Set GOAUTH_POSTGRES_TEST_DSN.
func BenchmarkLivePostgres_RefreshSession(b *testing.B) {
	a := liveBenchAuth(b, DriverPostgres, "GOAUTH_POSTGRES_TEST_DSN")
	ctx := context.Background()
	res, err := a.Register(ctx, RegisterInput{
		Email:    fmt.Sprintf("pgbench-r-%d@example.com", time.Now().UnixNano()),
		Password: validTestPassword(),
		Name:     "Bench",
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

// BenchmarkLiveMySQL_ValidateSession exercises session validation against a
// live MySQL server. Set GOAUTH_MYSQL_TEST_DSN
// (root:pass@tcp(host:port)/db?parseTime=true). This file's blank import of
// go-sql-driver/mysql registers the driver in this test binary.
func BenchmarkLiveMySQL_ValidateSession(b *testing.B) {
	a := liveBenchAuth(b, DriverMySQL, "GOAUTH_MYSQL_TEST_DSN")
	token := benchRegister(b, a, 0)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := a.Services.Auth.ValidateSession(ctx, token); err != nil {
			b.Fatal(err)
		}
	}
}
