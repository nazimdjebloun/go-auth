package migrations

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

func ownershipBaselineCatalog(t *testing.T, dialect string) Catalog {
	t.Helper()
	catalog, err := ReadCatalog(files, dialect)
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic upgrades always start from the immutable first baseline,
	// independently of later published migrations or canonical schema edits.
	catalog.Migrations = catalog.Migrations[:1:1]
	catalog.TargetRevision, catalog.Release = catalog.BootstrapRevision, "v0.4.0"
	return validateFixture(t, catalog)
}

func applyOwnershipBaseline(t *testing.T, db *sql.DB, dialect string) {
	t.Helper()
	if _, err := runCatalog(t.Context(), db, Options{Driver: dialect}, ownershipBaselineCatalog(t, dialect), "apply", 0); err != nil {
		t.Fatal(err)
	}
}

func appendOwnershipStep(t *testing.T, catalog Catalog, snapshot string, statements ...string) Catalog {
	t.Helper()
	id := catalog.TargetRevision + 1
	catalog.Migrations = append(catalog.Migrations, Step{
		ID: id, File: fmt.Sprintf("%06d_v0.%d.0_001.sql", id, id+3), Kind: "upgrade",
		Transactional: catalog.Dialect != "mysql", Schema: fmt.Sprintf("schema_%06d.sql", id),
		schemaSQL: snapshot, SQL: "-- goauth:statement\n" + strings.Join(statements, "\n-- goauth:statement\n") + "\n",
	})
	catalog.TargetRevision, catalog.Release = id, fmt.Sprintf("v0.%d.0", id+3)
	return validateFixture(t, catalog)
}

// These fixture-only upgrades retire an outbox name without changing any
// published schema or promising an actual outbox removal.
func retirementCatalog(t *testing.T, dialect, mode string) Catalog {
	t.Helper()
	catalog := ownershipBaselineCatalog(t, dialect)
	snapshot := catalog.Migrations[0].schemaSQL
	def, err := parseDefinition(dialect, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	commands := []string{"DROP TABLE audit_outbox"}
	if mode == "rename" {
		commands = []string{"ALTER TABLE audit_outbox RENAME TO archived_outbox"}
	} else {
		snapshot = strings.Replace(snapshot, def.tables["audit_outbox"].sql, "", 1)
	}
	for _, index := range indexDefinition.FindAllStringSubmatch(snapshot, -1) {
		if index[3] != "audit_outbox" {
			continue
		}
		if mode == "drop" {
			snapshot = strings.Replace(snapshot, index[0], "", 1)
			continue
		}
		drop := "DROP INDEX " + index[2]
		if dialect == "mysql" {
			drop += " ON archived_outbox"
		}
		commands = append(commands, drop, strings.ReplaceAll(index[0], "audit_outbox", "archived_outbox"))
	}
	if mode == "rename" {
		snapshot = strings.ReplaceAll(snapshot, "audit_outbox", "archived_outbox")
	}
	return appendOwnershipStep(t, catalog, snapshot, commands...)
}

func snapshotTableSQL(t *testing.T, dialect, snapshot, name string) []string {
	t.Helper()
	def, err := parseDefinition(dialect, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	commands := []string{def.tables[name].sql}
	for _, index := range indexDefinition.FindAllStringSubmatch(snapshot, -1) {
		if index[3] == name {
			commands = append(commands, index[0])
		}
	}
	return commands
}

func seedOwnershipHost(t *testing.T, db *sql.DB, dialect string) {
	t.Helper()
	upgradeExec(t, db, dialect, "CREATE TABLE host_notes (id INTEGER)")
	upgradeExec(t, db, dialect, "CREATE INDEX idx_host_notes ON host_notes(id)")
	upgradeExec(t, db, dialect, "INSERT INTO host_notes VALUES (42)")
}

func assertOwnershipHost(t *testing.T, db *sql.DB) {
	t.Helper()
	var id int
	if err := db.QueryRowContext(t.Context(), "SELECT id FROM host_notes").Scan(&id); err != nil || id != 42 {
		t.Fatal("unrelated application data changed", err)
	}
}

func TestSelectedBackendOwnedTableRetirement(t *testing.T) {
	t.Run("adoption reserves future names", func(t *testing.T) {
		db := testdb.OpenSelected(t)
		dialect := testdb.Driver(db)
		applyOwnershipBaseline(t, db, dialect)
		// Represent an existing bootstrap installation without tracked history.
		upgradeExec(t, db, dialect, "DROP TABLE goauth_migrations")
		catalog := retirementCatalog(t, dialect, "rename")
		upgradeExec(t, db, dialect, "CREATE TABLE archived_outbox (id INTEGER)")
		upgradeExec(t, db, dialect, "INSERT INTO archived_outbox VALUES (42)")
		if _, err := runCatalog(t.Context(), db, Options{Driver: dialect}, catalog, "adopt", 1); !errors.Is(err, ErrDrift) {
			t.Fatal("adoption accepted a future reserved-name collision", err)
		}
		if exists, err := objectExists(t.Context(), db, dialect, "goauth_migrations"); err != nil || exists {
			t.Fatal("refused adoption initialized history", err)
		}
		if err := verify(t.Context(), db, dialect, catalog.Migrations[0].schemaSQL, nil); err != nil {
			t.Fatal("refused adoption modified the existing baseline", err)
		}
		var id int
		if err := db.QueryRowContext(t.Context(), "SELECT id FROM archived_outbox").Scan(&id); err != nil || id != 42 {
			t.Fatal("refused adoption modified the colliding object", err)
		}
	})
	for _, mode := range []string{"drop", "rename"} {
		t.Run(mode, func(t *testing.T) {
			t.Run("apply", func(t *testing.T) {
				db := testdb.OpenSelected(t)
				dialect := testdb.Driver(db)
				seedOwnershipHost(t, db, dialect)
				catalog := retirementCatalog(t, dialect, mode)
				options := Options{Driver: dialect}
				if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); err != nil {
					t.Fatal("complete retirement failed", err)
				}
				if _, err := runCatalog(t.Context(), db, options, catalog, "verify", 0); err != nil {
					t.Fatal(err)
				}
				assertOwnershipHost(t, db)
			})
			t.Run("incomplete removal", func(t *testing.T) {
				db := testdb.OpenSelected(t)
				dialect := testdb.Driver(db)
				options := Options{Driver: dialect}
				applyOwnershipBaseline(t, db, dialect)
				seedOwnershipHost(t, db, dialect)
				catalog := retirementCatalog(t, dialect, mode)
				partial := []string{"SELECT TRUE"}
				if mode == "rename" {
					partial = snapshotTableSQL(t, dialect, catalog.Migrations[1].schemaSQL, "archived_outbox")
				}
				broken := validateFixture(t, catalog)
				broken.Migrations[1].statements = partial
				_, err := runCatalog(t.Context(), db, options, broken, "apply", 0)
				var failure *Error
				if !errors.Is(err, ErrDrift) || !errors.As(err, &failure) || failure.Phase != "postconditions" {
					t.Fatal("retirement without removing the old table completed", err)
				}
				state, err := readHistory(t.Context(), db, catalog)
				if err != nil || state.Revision != 1 || state.Dirty != (dialect == "mysql") {
					t.Fatalf("incorrect failure state: %+v, %v", state, err)
				}
				if dialect != "mysql" {
					// Transactional engines rolled back. Simulate an incomplete
					// journal explicitly; SQLite cannot naturally leave this state.
					if err := startRecord(t.Context(), db, catalog, catalog.Migrations[1], "executed"); err != nil {
						t.Fatal(err)
					}
					for _, command := range partial {
						upgradeExec(t, db, dialect, command)
					}
				}
				if _, err := runCatalog(t.Context(), db, options, catalog, "repair", 2); !errors.Is(err, ErrDrift) {
					t.Fatal("repair accepted an obsolete owned table", err)
				}
				state, err = readHistory(t.Context(), db, catalog)
				if err != nil || !state.Dirty || state.Revision != 1 || len(state.History) != 2 || state.History[1].CompletedAt != nil {
					t.Fatalf("failed repair changed the incomplete journal: %+v, %v", state, err)
				}
				upgradeExec(t, db, dialect, "DROP TABLE audit_outbox")
				if state, err = runCatalog(t.Context(), db, options, catalog, "repair", 2); err != nil || state.Dirty || state.Revision != 2 {
					t.Fatalf("reconciled retirement could not complete: %+v, %v", state, err)
				}
				if _, err := runCatalog(t.Context(), db, options, catalog, "verify", 0); err != nil {
					t.Fatal(err)
				}
				// A later unchanged snapshot must retain ownership of names
				// that disappeared more than one migration ago.
				catalog = appendOwnershipStep(t, catalog, catalog.Migrations[1].schemaSQL, "SELECT TRUE")
				upgradeExec(t, db, dialect, "CREATE TABLE audit_outbox (id INTEGER)")
				if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); !errors.Is(err, ErrDrift) {
					t.Fatal("preflight ignored a retired owned name", err)
				}
				state, err = readHistory(t.Context(), db, catalog)
				if err != nil || state.Dirty || len(state.History) != 2 {
					t.Fatalf("preflight changed history: %+v, %v", state, err)
				}
				upgradeExec(t, db, dialect, "DROP TABLE audit_outbox")
				if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); err != nil {
					t.Fatal(err)
				}
				upgradeExec(t, db, dialect, "CREATE TABLE audit_outbox (id INTEGER)")
				if _, err := runCatalog(t.Context(), db, options, catalog, "verify", 0); !errors.Is(err, ErrDrift) {
					t.Fatal("target verification forgot a historical owned name", err)
				}
				assertOwnershipHost(t, db)
			})
		})
	}
}

func TestSelectedBackendOwnedTableRetry(t *testing.T) {
	for _, mode := range []string{"add", "rename"} {
		t.Run(mode, func(t *testing.T) {
			db := testdb.OpenSelected(t)
			dialect := testdb.Driver(db)
			options := Options{Driver: dialect}
			applyOwnershipBaseline(t, db, dialect)
			catalog := retirementCatalog(t, dialect, "rename")
			name := "archived_outbox"
			if mode == "add" {
				catalog = ownershipBaselineCatalog(t, dialect)
				name = "added_owned_table"
				ddl := "CREATE TABLE added_owned_table (\n    id INTEGER PRIMARY KEY\n)"
				if dialect == "mysql" {
					ddl += " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
				}
				ddl += ";\n"
				catalog = appendOwnershipStep(t, catalog, catalog.Migrations[0].schemaSQL+"\n"+ddl, ddl)
			}
			if dialect != "sqlite" {
				catalog.Migrations[1].Transactional = false
				catalog.Migrations[1].Retry = &RetryPolicy{Checks: []string{"SELECT TRUE"}, Instructions: "Remove partial additions before retrying."}
				catalog = validateFixture(t, catalog)
			}
			if err := startRecord(t.Context(), db, catalog, catalog.Migrations[1], "executed"); err != nil {
				t.Fatal(err)
			}
			for _, command := range snapshotTableSQL(t, dialect, catalog.Migrations[1].schemaSQL, name) {
				upgradeExec(t, db, dialect, command)
			}
			if dialect == "sqlite" {
				// SQLite has no nontransactional retry. Exercise the same
				// starting-schema verifier directly against a simulated state.
				if err := verifyStep(t.Context(), db, catalog, catalog.Migrations[0], time.Second); !errors.Is(err, ErrDrift) {
					t.Fatal("starting schema accepted a partial addition", err)
				}
			} else if _, err := runCatalog(t.Context(), db, options, catalog, "retry", 2); !errors.Is(err, ErrDrift) {
				t.Fatal("retry accepted a partial addition", err)
			}
			state, err := readHistory(t.Context(), db, catalog)
			if err != nil || !state.Dirty || state.Revision != 1 || len(state.History) != 2 || state.History[1].CompletedAt != nil {
				t.Fatalf("refused retry changed history: %+v, %v", state, err)
			}
			upgradeExec(t, db, dialect, "DROP TABLE "+name)
			if dialect == "sqlite" {
				if err := verifyStep(t.Context(), db, catalog, catalog.Migrations[0], time.Second); err != nil {
					t.Fatal("restored starting schema failed", err)
				}
			} else if state, err = runCatalog(t.Context(), db, options, catalog, "retry", 2); err != nil || state.Dirty || state.Revision != 2 {
				t.Fatalf("reconciled retry failed: %+v, %v", state, err)
			}
		})
	}
}

func TestSelectedBackendOwnedObjectNamespaces(t *testing.T) {
	db := testdb.OpenSelected(t)
	db.SetMaxOpenConns(1)
	dialect := testdb.Driver(db)
	options := Options{Driver: dialect}
	catalog := retirementCatalog(t, dialect, "drop")
	seedOwnershipHost(t, db, dialect)
	if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); err != nil {
		t.Fatal(err)
	}
	upgradeExec(t, db, dialect, "CREATE INDEX idx_audit_outbox_claim ON host_notes(id)")
	_, err := runCatalog(t.Context(), db, options, catalog, "verify", 0)
	if dialect == "mysql" {
		if err != nil {
			t.Fatal("host index collided with a table-scoped auth index name", err)
		}
	} else if !errors.Is(err, ErrDrift) {
		t.Fatal("verification accepted a retired reserved index name", err)
	}
	drop := "DROP INDEX idx_audit_outbox_claim"
	if dialect == "mysql" {
		drop += " ON host_notes"
	}
	upgradeExec(t, db, dialect, drop)
	if dialect == "postgres" {
		upgradeExec(t, db, dialect, "CREATE SCHEMA host_archive")
		upgradeExec(t, db, dialect, "CREATE TABLE host_archive.audit_outbox (id INTEGER)")
		upgradeExec(t, db, dialect, "CREATE INDEX idx_audit_outbox_claim ON host_archive.audit_outbox(id)")
		upgradeExec(t, db, dialect, "SET search_path=public,host_archive")
	}
	if _, err := runCatalog(t.Context(), db, options, catalog, "verify", 0); err != nil {
		t.Fatal("unrelated host objects prevented verification", err)
	}
	// Reusing a retired name in a later published snapshot is valid; its new
	// definition must be verified instead of requiring perpetual absence.
	catalog = appendOwnershipStep(t, catalog, catalog.Migrations[0].schemaSQL,
		snapshotTableSQL(t, dialect, catalog.Migrations[0].schemaSQL, "audit_outbox")...)
	if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); err != nil {
		t.Fatal("catalog could not reuse an owned name", err)
	}
	assertOwnershipHost(t, db)
}
