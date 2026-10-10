package goauth

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestNewSchemaCheckRejectsUntrackedAndDirtyBorrowedDatabase(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "auth.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	cfg, err := NewConfig(minimalOpts(WithApp(AppConfig{
		Name: "schema-check", BaseURL: "http://localhost:3000", Environment: EnvironmentDev,
		Database: DatabaseConfig{DB: db, Driver: DriverSQLite, CheckSchema: true},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	if auth, err := New(cfg); !errors.Is(err, ErrUntrackedSchema) || auth != nil {
		if auth != nil {
			auth.Close()
		}
		t.Fatalf("untracked startup was accepted: %v", err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_schema WHERE name='goauth_migrations'").Scan(&count); err != nil || count != 0 {
		t.Fatal("startup created migration metadata or closed the borrowed database", err)
	}
	if _, err := Migrate(t.Context(), db, MigrationOptions{Driver: "sqlite"}); err != nil {
		t.Fatal(err)
	}
	auth, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	auth.Close()
	if _, err := db.Exec("UPDATE goauth_migrations SET state='started', completed_at=NULL"); err != nil {
		t.Fatal("Auth.Close closed the borrowed database", err)
	}
	if auth, err := New(cfg); !errors.Is(err, ErrDirtyMigration) || auth != nil {
		if auth != nil {
			auth.Close()
		}
		t.Fatalf("dirty startup was accepted: %v", err)
	}
	if err := db.PingContext(t.Context()); err != nil {
		t.Fatal("failed construction closed the borrowed database", err)
	}
}

func TestCompatibilityCheckDoesNotClaimStructuralVerification(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Migrate(t.Context(), db, MigrationOptions{Driver: "sqlite"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DROP INDEX idx_users_app_role"); err != nil {
		t.Fatal(err)
	}
	if err := CheckSchema(t.Context(), db, "sqlite"); err != nil {
		t.Fatal("compatibility metadata unexpectedly changed", err)
	}
	if err := VerifySchema(t.Context(), db, MigrationOptions{Driver: "sqlite"}); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("live structural drift was not detected: %v", err)
	}
}
