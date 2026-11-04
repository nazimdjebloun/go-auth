package goauth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewRejectsUnreachableBorrowedPool(t *testing.T) {
	pool, err := pgxpool.New(t.Context(), "postgres://user:pass@127.0.0.1:1/db?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	cfg, err := NewConfig(minimalOpts(WithApp(AppConfig{
		Name: "startup", BaseURL: "https://example.com",
		Database: DatabaseConfig{Driver: DriverPostgres, Pool: pool},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := New(cfg)
	if auth != nil || err == nil || !strings.Contains(err.Error(), "startup database connection") {
		if auth != nil {
			auth.Close()
		}
		t.Fatalf("unreachable borrowed pool accepted: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if _, err := pool.Acquire(ctx); err == nil || strings.Contains(err.Error(), "closed pool") {
		t.Fatalf("startup failure changed ownership of the borrowed pool: %v", err)
	}
}

func TestNewRejectsInvalidRecordedHistoryByDefault(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
		want error
	}{
		{"pending upgrade", "DELETE FROM goauth_migrations WHERE migration_id=(SELECT MAX(migration_id) FROM goauth_migrations)", ErrIncompatibleSchema},
		{"checksum changed", "UPDATE goauth_migrations SET checksum='invalid' WHERE migration_id=(SELECT MAX(migration_id) FROM goauth_migrations)", ErrMigrationChecksum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newHasherTestDB(t)
			if _, err := db.ExecContext(t.Context(), tc.sql); err != nil {
				t.Fatal(err)
			}
			cfg, err := NewConfig(minimalOpts(WithApp(AppConfig{
				Name: "startup", BaseURL: "https://example.com",
				Database: DatabaseConfig{Driver: DriverSQLite, DB: db},
			}))...)
			if err != nil {
				t.Fatal(err)
			}
			auth, err := New(cfg)
			if auth != nil || !errors.Is(err, tc.want) || !strings.Contains(err.Error(), "migrations before startup") {
				if auth != nil {
					auth.Close()
				}
				t.Fatalf("invalid schema history accepted: %v", err)
			}
			if err := db.PingContext(t.Context()); err != nil {
				t.Fatal("startup failure closed a borrowed database", err)
			}
		})
	}
}
