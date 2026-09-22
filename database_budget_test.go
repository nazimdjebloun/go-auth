package goauth

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestDatabaseBudget_DefaultOwnedSQLite(t *testing.T) {
	cfg := &Config{app: AppConfig{Database: DatabaseConfig{Driver: DriverSQLite, URL: filepath.Join(t.TempDir(), "budget.db")}}}
	_, db, err := openDatabase(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if got := db.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("SQLite max connections = %d, want 1", got)
	}
}

func TestDatabaseBudget_BorrowedPoolAdapterIsOwned(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://user:pass@127.0.0.1:1/db")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	cfg := &Config{app: AppConfig{Database: DatabaseConfig{Driver: DriverPostgres, Pool: pool}}}
	_, db, err := openDatabase(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if !cfg.app.Database.opened {
		t.Fatal("library-created SQL adapter has no cleanup owner")
	}
}
