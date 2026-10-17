package migrations

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

func frozenFixture(t *testing.T, catalog Catalog) fstest.MapFS {
	t.Helper()
	source := fstest.MapFS{}
	for _, step := range catalog.Migrations {
		source[catalog.Dialect+"/"+step.File] = &fstest.MapFile{Data: []byte(step.SQL)}
		source[catalog.Dialect+"/"+step.Schema] = &fstest.MapFile{Data: []byte(step.schemaSQL)}
	}
	manifest, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	source[catalog.Dialect+"/catalog.json"] = &fstest.MapFile{Data: manifest}
	return source
}

func TestCatalogRejectsUnsafeRetryMetadata(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Catalog)
		valid  bool
	}{
		{"published policy", func(*Catalog) {}, true},
		{"transactional", func(c *Catalog) { c.Migrations[1].Transactional = true }, false},
		{"baseline", func(c *Catalog) { c.Migrations[0].Retry = c.Migrations[1].Retry }, false},
		{"missing checks", func(c *Catalog) { c.Migrations[1].Retry.Checks = nil }, false},
		{"missing instructions", func(c *Catalog) { c.Migrations[1].Retry.Instructions = "  " }, false},
		{"mutating retry query", func(c *Catalog) { c.Migrations[1].Retry.Checks = []string{"DELETE FROM users"} }, false},
		{"mutating precondition", func(c *Catalog) { c.Migrations[1].Preconditions = []string{"UPDATE users SET name=''"} }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := upgradeCatalog(t, "postgres")
			catalog.Migrations[1].Transactional = false
			catalog.Migrations[1].Retry = &RetryPolicy{Checks: []string{"SELECT TRUE"}, Instructions: "Verify the previous data state before retrying."}
			test.mutate(&catalog)
			_, err := ReadCatalog(frozenFixture(t, catalog), catalog.Dialect)
			if (err == nil) != test.valid {
				t.Fatalf("metadata acceptance=%t, want %t: %v", err == nil, test.valid, err)
			}
		})
	}
}

func TestCatalogRejectsUnknownFieldsAndTrailingContent(t *testing.T) {
	catalog, err := Load("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"unknown", "trailing"} {
		t.Run(mutation, func(t *testing.T) {
			source := frozenFixture(t, catalog)
			manifest := source["sqlite/catalog.json"].Data
			if mutation == "unknown" {
				manifest = []byte(strings.Replace(string(manifest), `"checks":`, `"preconditons":[],"checks":`, 1))
			} else {
				manifest = append(manifest, []byte(" {}")...)
			}
			source["sqlite/catalog.json"].Data = manifest
			if _, err := ReadCatalog(source, "sqlite"); err == nil {
				t.Fatal("an ambiguous catalog was accepted")
			}
		})
	}
}

func TestPreconditionsRequireExactlyOneTrueValue(t *testing.T) {
	db := migrationDB(t)
	options := Options{StatementTimeout: time.Second}
	for _, query := range []string{
		"SELECT FALSE", "SELECT TRUE WHERE FALSE", "SELECT TRUE UNION ALL SELECT TRUE",
		"SELECT NULL", "SELECT TRUE, TRUE", "SELECT 'not a boolean'",
	} {
		t.Run(query, func(t *testing.T) {
			if err := checkPreconditions(t.Context(), db, Step{Preconditions: []string{query}}, options); !errors.Is(err, ErrPrecondition) {
				t.Fatal("invalid prerequisite result was accepted", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := checkPreconditions(ctx, db, Step{Preconditions: []string{"SELECT TRUE"}}, options); !errors.Is(err, context.Canceled) {
		t.Fatal("prerequisite cancellation lost its cause", err)
	}
}

func TestSelectedBackendVerifiedRetry(t *testing.T) {
	db := testdb.OpenSelected(t)
	dialect := testdb.Driver(db)
	options := Options{Driver: dialect}
	if _, err := Apply(t.Context(), db, options); err != nil {
		t.Fatal(err)
	}
	hash, password := seedUpgradeData(t, db, dialect)
	catalog := upgradeCatalog(t, dialect)
	catalog.Migrations[1].Preconditions = []string{"SELECT COUNT(*)=0 FROM users WHERE name='prerequisite-missing'"}
	if dialect != "sqlite" {
		catalog.Migrations[1].Transactional = false
		catalog.Migrations[1].Retry = &RetryPolicy{
			Checks:       []string{"SELECT COUNT(*)=0 FROM users WHERE name='retry-blocked'"},
			Instructions: "Inspect partial DDL and reconcile to the previous verified schema and data before full replay.",
		}
	}
	catalog = validateFixture(t, catalog)
	blockedNames := []string{"prerequisite-missing"}
	if dialect != "sqlite" {
		blockedNames = append(blockedNames, "retry-blocked")
	}
	for _, name := range blockedNames {
		upgradeExec(t, db, dialect, "UPDATE users SET name=? WHERE id=?", name, upgradeUser)
		status, err := runCatalog(t.Context(), db, options, catalog, "apply", 0)
		if !errors.Is(err, ErrPrecondition) || status.Dirty || status.Revision != 1 {
			t.Fatalf("failed precondition mutated history: %+v, %v", status, err)
		}
		status, err = readHistory(t.Context(), db, catalog)
		if err != nil || len(status.History) != 1 || status.Dirty {
			t.Fatal("data preflight created an incomplete record", err)
		}
		if err := verifyStep(t.Context(), db, catalog, catalog.Migrations[0]); err != nil {
			t.Fatal("data preflight ran schema mutations", err)
		}
	}
	upgradeExec(t, db, dialect, "UPDATE users SET name='Password' WHERE id=?", upgradeUser)
	if dialect == "sqlite" {
		if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); err != nil {
			t.Fatal(err)
		}
		if _, err := runCatalog(t.Context(), db, options, catalog, "retry", 2); !errors.Is(err, ErrDirty) {
			t.Fatal("clean transactional history was retried", err)
		}
		assertUpgradeData(t, db, dialect, hash, password)
		return
	}
	broken := validateFixture(t, catalog)
	broken.Migrations[1].statements[0] = "INSERT INTO missing_retry_failure_table VALUES (1)"
	if _, err := runCatalog(t.Context(), db, options, broken, "apply", 0); err == nil {
		t.Fatal("injected nontransactional failure succeeded")
	}
	upgradeExec(t, db, dialect, "UPDATE goauth_migrations SET started_at=123456789 WHERE migration_id=2")
	if _, err := runCatalog(t.Context(), db, options, catalog, "retry", 3); !errors.Is(err, ErrDirty) {
		t.Fatal("a different incomplete ID was accepted", err)
	}
	noPolicy := validateFixture(t, catalog)
	noPolicy.Migrations[1].Retry = nil
	if _, err := runCatalog(t.Context(), db, options, noPolicy, "retry", 2); !errors.Is(err, ErrRetryUnsupported) {
		t.Fatal("unpublished retry was accepted", err)
	}
	upgradeExec(t, db, dialect, "UPDATE users SET name='retry-blocked' WHERE id=?", upgradeUser)
	if _, err := runCatalog(t.Context(), db, options, catalog, "retry", 2); !errors.Is(err, ErrPrecondition) {
		t.Fatal("failed starting data checks allowed retry", err)
	}
	upgradeExec(t, db, dialect, "UPDATE users SET name='Password' WHERE id=?", upgradeUser)
	upgradeExec(t, db, dialect, "ALTER TABLE users ADD COLUMN migration_note VARCHAR(255)")
	if _, err := runCatalog(t.Context(), db, options, catalog, "retry", 2); !errors.Is(err, ErrDrift) {
		t.Fatal("partial DDL was blindly replayed", err)
	}
	upgradeExec(t, db, dialect, "ALTER TABLE users DROP COLUMN migration_note")
	if _, err := runCatalog(t.Context(), db, options, broken, "retry", 2); err == nil {
		t.Fatal("a second injected execution failure succeeded")
	}
	status, err := readHistory(t.Context(), db, catalog)
	if err != nil || !status.Dirty || len(status.History) != 2 || status.History[1].StartedAt != 123456789 {
		t.Fatalf("retry failure replaced or cleaned the journal: %+v, %v", status, err)
	}
	// Two retry attempts must serialize before inspecting the incomplete record.
	// The second observes completion and refuses to replay the same SQL again.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	other := testdb.SecondPool(t, db)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, pool := range []*sql.DB{db, other} {
		go func() {
			<-start
			_, err := runCatalog(ctx, pool, options, catalog, "retry", 2)
			results <- err
		}()
	}
	close(start)
	completed, refused := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			completed++
		case errors.Is(err, ErrDirty):
			refused++
		default:
			t.Fatal("concurrent verified retry failed", err)
		}
	}
	if completed != 1 || refused != 1 {
		t.Fatal("concurrent retries both executed or both refused")
	}
	status, err = readHistory(t.Context(), db, catalog)
	if err != nil || status.Dirty || status.Revision != 2 || len(status.Pending) != 1 ||
		len(status.History) != 2 || status.History[1].StartedAt != 123456789 {
		t.Fatalf("retry ran later steps or replaced history: %+v, %v", status, err)
	}
	if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); err != nil {
		t.Fatal("remaining steps could not follow verified retry", err)
	}
	assertUpgradeData(t, db, dialect, hash, password)
}
