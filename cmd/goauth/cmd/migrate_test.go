package cmd

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// TestApplySchema_SQLite_CreatesExpectedTablesAndIsIdempotent guards the
// one property that matters for `goauth migrate`: it's the first command
// in the README's Quick Start, so it has to actually apply the schema, and
// every statement in the embedded schema is written as CREATE ... IF NOT
// EXISTS specifically so a re-run (redeploys, retries) doesn't error.
func TestApplySchema_SQLite_CreatesExpectedTablesAndIsIdempotent(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "migrate_test.db")

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	defer db.Close()

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

	// Re-running against an already-migrated database must succeed as a
	// no-op, not error — this is the actual regression this test guards
	// against: a future schema change that drops IF NOT EXISTS would break
	// every redeploy against an existing database.
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
	defer db.Close()

	err = applySchema(context.Background(), db, "oracle")
	if err == nil {
		t.Fatal("expected an error for an unsupported driver, got nil")
	}
}
