package goauth

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type budgetFailureProvider struct {
	mockProvider
	probe func()
}

func (p *budgetFailureProvider) Name() string {
	p.probe()
	return ""
}

func TestDatabaseBudget_ConstructorFailureClosesOwnedDB(t *testing.T) {
	// Shared memory survives only while at least one connection stays open.
	// The provider probe closes its own connection before New returns; a
	// leaked library connection would keep this marker table alive.
	dsn := "file:" + filepath.ToSlash(filepath.Join(t.TempDir(), "cleanup")) + "?mode=memory&cache=shared"
	cfg, err := NewConfig(minimalOpts(WithApp(AppConfig{
		Name: "app", BaseURL: "https://example.com",
		Database: DatabaseConfig{Driver: DriverSQLite, URL: dsn},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	cfg.providers = append(cfg.providers, &budgetFailureProvider{probe: func() {
		probe, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = probe.Close() }()
		if _, err := probe.Exec("CREATE TABLE cleanup_marker (id INTEGER)"); err != nil {
			t.Fatal(err)
		}
	}})
	if a, err := New(cfg); err == nil || !strings.Contains(err.Error(), "empty name") {
		if a != nil {
			a.Close()
		}
		t.Fatalf("expected late provider failure, got %v", err)
	}
	probe, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	var count int
	if err := probe.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name = 'cleanup_marker'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("constructor failure leaked the owned connection")
	}
}

func TestDatabaseBudget_CloseOwnedAndPreserveBorrowedOnFailure(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithApp(AppConfig{
		Name: "app", BaseURL: "https://example.com",
		Database: DatabaseConfig{Driver: DriverSQLite, URL: ":memory:"},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if err := a.db.Ping(); err == nil {
		t.Fatal("owned DB still open after Close")
	}

	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	cfg.app.Database = DatabaseConfig{Driver: DriverSQLite, DB: db}
	cfg.providers = append(cfg.providers, nil)
	if a, err := New(cfg); err == nil {
		a.Close()
		t.Fatal("expected invalid provider error")
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("failure closed borrowed DB: %v", err)
	}
}

func TestDatabaseBudget_PostgresURL(t *testing.T) {
	dsn := os.Getenv("GOAUTH_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set GOAUTH_POSTGRES_TEST_DSN for live PostgreSQL pool validation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := &Config{app: AppConfig{Database: DatabaseConfig{Driver: DriverPostgres, URL: dsn, MaxOpenConns: 3}}}
	pool, db, err := openDatabase(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if pool != nil {
		t.Fatal("URL path created a redundant pgx pool")
	}
	if got := db.Stats().MaxOpenConnections; got != 3 {
		t.Fatalf("max connections=%d", got)
	}
}
