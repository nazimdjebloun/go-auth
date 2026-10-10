package migrations

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

func TestPostgres_MigrationPoolDiscard(t *testing.T) {
	if testdb.Selected() != "postgres" {
		t.Skip("PostgreSQL backend required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	db := testdb.OpenSelected(t)
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var config *pgx.ConnConfig
	err = conn.Raw(func(raw any) error {
		config = raw.(*stdlib.Conn).Conn().Config().Copy()
		return nil
	})
	if closeErr := conn.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	poolConfig, err := pgxpool.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig, poolConfig.MaxConns = config, 1
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	adapter := stdlib.OpenDBFromPool(pool)
	defer func() { _ = adapter.Close() }()
	catalog, err := Load("postgres")
	if err != nil {
		t.Fatal(err)
	}
	options, err := (Options{Driver: "postgres"}).defaults()
	if err != nil {
		t.Fatal(err)
	}
	l, err := acquire(ctx, adapter, catalog, options)
	if err != nil {
		t.Fatal(err)
	}
	var physical *pgx.Conn
	err = l.conn.Raw(func(raw any) error {
		physical = raw.(*stdlib.Conn).Conn()
		return nil
	})
	if err != nil {
		_ = l.close(ctx, false)
		t.Fatal(err)
	}
	// A lost lock must discard the physical connection even when driver.Close
	// normally returns it to the native pool.
	if _, err := l.conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", advisoryKey); err != nil {
		_ = l.close(ctx, false)
		t.Fatal(err)
	}
	if err := l.close(ctx, false); err == nil || !strings.Contains(err.Error(), "ownership was lost") {
		t.Fatalf("lost lock ownership was accepted: %v", err)
	}
	if !physical.IsClosed() {
		t.Fatal("uncertain connection was returned to the native pool")
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatal("borrowed native pool was closed", err)
	}
	if err := adapter.PingContext(ctx); err != nil {
		t.Fatal("borrowed SQL adapter was closed", err)
	}
}
