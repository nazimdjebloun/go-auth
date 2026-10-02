package goauth

import (
	"bytes"
	"database/sql"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func TestNewConfigDoesNotAllocateOwnedRateLimitResources(t *testing.T) {
	for _, valid := range []bool{true, false} {
		var captured *Config
		opts := minimalOpts(func(c *Config) { captured = c })
		if !valid {
			opts = append(opts, WithSecret("short"))
		}
		cfg, err := NewConfig(opts...)
		if (err == nil) != valid {
			t.Fatalf("valid=%v: config=%v error=%v", valid, cfg, err)
		}
		if captured.rateLimit.Store != nil {
			t.Fatalf("valid=%v: NewConfig allocated an owned store", valid)
		}
	}
}

func TestNewReusedConfigHasIndependentRateLimitStores(t *testing.T) {
	db := testdb.Open(t, "sqlite", "")
	testdb.Apply(t, db)
	cfg, err := NewConfig(minimalOpts(
		WithApp(AppConfig{Name: "app", BaseURL: "https://example.com", Database: DatabaseConfig{Driver: DriverSQLite, DB: db}}),
		WithBcryptCost(4),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if cfg.rateLimit.Store != nil || a.cfg.rateLimit.Store == b.cfg.rateLimit.Store {
		t.Fatal("reusing a configuration shared an owned store")
	}
	rate := ratelimit.Rate{Requests: 1, Window: time.Hour}
	for i, store := range []ratelimit.Store{a.cfg.rateLimit.Store, b.cfg.rateLimit.Store} {
		result, err := store.Allow(t.Context(), "same client and route", rate)
		if err != nil || !result.Allowed {
			t.Fatalf("instance %d inherited another instance's counter: %+v, %v", i, result, err)
		}
		result, err = store.Allow(t.Context(), "same client and route", rate)
		if err != nil || result.Allowed {
			t.Fatalf("instance %d did not enforce its own counter: %+v, %v", i, result, err)
		}
	}
	a.Close()
	if result, err := b.cfg.rateLimit.Store.Allow(t.Context(), "new client", rate); err != nil || !result.Allowed {
		t.Fatalf("closing the first instance affected the second: %+v, %v", result, err)
	}
}

func TestNewDisabledRateLimitDoesNotAllocateStore(t *testing.T) {
	a := buildAuth(t, minimalOpts(WithRateLimitEnabled(false), WithBcryptCost(4))...)
	t.Cleanup(a.Close)
	if a.cfg.rateLimit.Store != nil {
		t.Fatal("disabled rate limiting allocated an owned store")
	}
}

func memoryStoreWorkers(t *testing.T) int {
	t.Helper()
	var stacks bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&stacks, 2); err != nil {
		t.Fatal(err)
	}
	return strings.Count(stacks.String(), "ratelimit.(*memoryStore).cleanup(")
}

func TestNewStartupFailureDoesNotLeakRateLimitWorkers(t *testing.T) {
	// Force a failure after config validation and database setup, during
	// stored pepper-version validation, by supplying an empty database.
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg, err := NewConfig(minimalOpts(
		WithApp(AppConfig{Name: "app", BaseURL: "https://example.com", Database: DatabaseConfig{Driver: DriverSQLite, DB: db}}),
		WithBcryptCost(4),
		WithPasswordPepper(PasswordPepperConfig{CurrentVersion: 1, Keys: map[uint32]string{1: strings.Repeat("p", 32)}}),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	before := memoryStoreWorkers(t)
	for range 5 {
		if a, err := New(cfg); err == nil || a != nil {
			t.Fatalf("missing schema did not fail startup: %v", err)
		}
	}
	if after := memoryStoreWorkers(t); after != before {
		t.Fatalf("failed startup leaked memory-store workers: before=%d after=%d", before, after)
	}
}
