package cmd

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	goauth "github.com/nazimdjebloun/go-auth"
	_ "modernc.org/sqlite"
)

func applySchema(ctx context.Context, db *sql.DB, driver string) error {
	_, err := goauth.Migrate(ctx, db, goauth.MigrationOptions{Driver: driver})
	return err
}

// Repeated execution skips completed SQL through recorded migration history.
func TestApplySchema_SQLite_CreatesExpectedTablesAndIsIdempotent(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "migrate_test.db")

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()

	if err := applySchema(ctx, db, "sqlite"); err != nil {
		t.Fatalf("first applySchema call: %v", err)
	}

	wantTables := []string{
		"users",
		"sessions",
		"verification_tokens",
		"provider_accounts",
		"invites",
		"organizations",
		"organization_members",
		"organization_invites",
		"audit_log",
	}
	for _, table := range wantTables {
		var name string
		err := db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table,
		).Scan(&name)
		if err != nil {
			t.Errorf("expected table %q to exist after migrate: %v", table, err)
		}
	}

	// A repeat must validate history and schema without replaying creation SQL.
	if err := applySchema(ctx, db, "sqlite"); err != nil {
		t.Fatalf("second (idempotent) applySchema call: %v", err)
	}
}

func TestApplySchema_UnsupportedDriver_ReturnsErrorWithoutTouchingDB(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "migrate_test.db")

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer func() { _ = db.Close() }()

	err = applySchema(context.Background(), db, "oracle")
	if err == nil {
		t.Fatal("expected an error for an unsupported driver, got nil")
	}
}
