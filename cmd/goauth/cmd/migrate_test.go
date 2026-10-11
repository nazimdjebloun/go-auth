package cmd

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"path/filepath"
	"strings"
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

func TestRetryCommandRequiresPositiveIDBeforeOpeningDatabase(t *testing.T) {
	for _, id := range []string{"", "0", "-1"} {
		t.Run("id="+id, func(t *testing.T) {
			cmd := newMigrateCommand()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			args := []string{"retry", "--driver", "sqlite", "--dsn", "never-opened"}
			if id != "" {
				args = append(args, "--id", id)
			}
			cmd.SetArgs(args)
			if err := cmd.ExecuteContext(t.Context()); err == nil || !strings.Contains(err.Error(), "id") {
				t.Fatal("invalid retry ID reached database execution", err)
			}
		})
	}
}

func TestRetryCommandRefusesBaselineWithoutPublishedPolicy(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "retry.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := applySchema(t.Context(), db, "sqlite"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE goauth_migrations SET state='started', completed_at=NULL"); err != nil {
		t.Fatal(err)
	}
	cmd := newMigrateCommand()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"retry", "--driver", "sqlite", "--dsn", dsn, "--id", "1"})
	err = cmd.ExecuteContext(t.Context())
	if !errors.Is(err, goauth.ErrMigrationRetryUnsupported) || strings.Contains(err.Error(), dsn) {
		t.Fatal("unsupported retry or safe diagnostics were lost", err)
	}
}
