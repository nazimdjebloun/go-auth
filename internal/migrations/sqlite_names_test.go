package migrations

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

type sqliteNameCollision struct{ name, create, drop string }

func sqliteNameCollisions(table string) []sqliteNameCollision {
	var cases []sqliteNameCollision
	for _, names := range []struct{ label, table, index string }{
		{"uppercase", strings.ToUpper(table), strings.ToUpper("idx_" + table + "_claim")},
		{"mixed case", strings.ToUpper(table[:1]) + table[1:], "Idx_" + table + "_claim"},
	} {
		cases = append(cases,
			sqliteNameCollision{names.label + " table", "CREATE TABLE " + names.table + " (id INTEGER)", "DROP TABLE " + names.table},
			sqliteNameCollision{names.label + " index", "CREATE INDEX " + names.index + " ON host_notes(id)", "DROP INDEX " + names.index},
			sqliteNameCollision{names.label + " view", "CREATE VIEW " + names.table + " AS SELECT id FROM host_notes", "DROP VIEW " + names.table},
		)
	}
	return cases
}

func TestSQLiteFreshReservedNamesIgnoreASCIICase(t *testing.T) {
	for _, scope := range []string{"current", "pending"} {
		t.Run(scope, func(t *testing.T) {
			table := "audit_outbox"
			catalog := bootstrapCatalog(t, "sqlite")
			if scope == "pending" {
				table = "archived_outbox"
				catalog = retirementCatalog(t, "sqlite", "rename")
			}
			for _, collision := range sqliteNameCollisions(table) {
				t.Run(collision.name, func(t *testing.T) {
					db := migrationDB(t)
					seedOwnershipHost(t, db, "sqlite")
					upgradeExec(t, db, "sqlite", collision.create)
					_, err := runCatalog(t.Context(), db, Options{Driver: "sqlite"}, catalog, "apply", 0)
					var failure *Error
					if !errors.Is(err, ErrUntracked) || !errors.As(err, &failure) || failure.Phase != "baseline preflight" {
						t.Fatal("fresh installation did not reject a reserved-name collision before execution", err)
					}
					for _, name := range []string{"users", "goauth_migrations"} {
						if exists, err := objectExists(t.Context(), db, "sqlite", name); err != nil || exists {
							t.Fatal("refused installation initialized auth schema or history", name, err)
						}
					}
					// Dropping the original object also confirms refusal preserved it.
					upgradeExec(t, db, "sqlite", collision.drop)
					assertOwnershipHost(t, db)
				})
			}
		})
	}
}

func TestSQLiteAdoptionReservesNamesIgnoringASCIICase(t *testing.T) {
	catalog := retirementCatalog(t, "sqlite", "rename")
	for _, collision := range sqliteNameCollisions("archived_outbox") {
		t.Run(collision.name, func(t *testing.T) {
			db := migrationDB(t)
			applyBootstrap(t, db, "sqlite")
			upgradeExec(t, db, "sqlite", "DROP TABLE goauth_migrations")
			seedOwnershipHost(t, db, "sqlite")
			upgradeExec(t, db, "sqlite", collision.create)
			_, err := runCatalog(t.Context(), db, Options{Driver: "sqlite"}, catalog, "adopt", 1)
			var failure *Error
			if !errors.Is(err, ErrDrift) || !errors.As(err, &failure) || failure.Phase != "adoption validation" {
				t.Fatal("adoption accepted a pending reserved-name collision", err)
			}
			if exists, err := objectExists(t.Context(), db, "sqlite", "goauth_migrations"); err != nil || exists {
				t.Fatal("refused adoption initialized history", err)
			}
			if err := verify(t.Context(), db, "sqlite", catalog.Migrations[0].schemaSQL, nil); err != nil {
				t.Fatal("refused adoption modified the baseline", err)
			}
			upgradeExec(t, db, "sqlite", collision.drop)
			assertOwnershipHost(t, db)
		})
	}
}

func TestSQLiteRetiredNamesIgnoreASCIICase(t *testing.T) {
	catalog := retirementCatalog(t, "sqlite", "drop")
	options := Options{Driver: "sqlite"}
	for _, collision := range sqliteNameCollisions("audit_outbox") {
		t.Run(collision.name, func(t *testing.T) {
			db := migrationDB(t)
			seedOwnershipHost(t, db, "sqlite")
			installed, err := runCatalog(t.Context(), db, options, catalog, "apply", 0)
			if err != nil {
				t.Fatal(err)
			}
			upgradeExec(t, db, "sqlite", collision.create)
			for _, operation := range []string{"verify", "apply"} {
				if _, err := runCatalog(t.Context(), db, options, catalog, operation, 0); !errors.Is(err, ErrDrift) {
					t.Fatal("accepted a retired reserved-name collision", operation, err)
				}
			}
			state, err := readHistory(t.Context(), db, catalog)
			if err != nil || !reflect.DeepEqual(installed.History, state.History) {
				t.Fatal("refused verification or preflight changed history", err)
			}
			upgradeExec(t, db, "sqlite", collision.drop)
			if _, err := runCatalog(t.Context(), db, options, catalog, "verify", 0); err != nil {
				t.Fatal("removing the collision did not restore verification", err)
			}
			assertOwnershipHost(t, db)
		})
	}
}

func TestSQLiteHostTriggersUseSeparateNamespace(t *testing.T) {
	for _, mode := range []string{"drop", "rename"} {
		t.Run(mode, func(t *testing.T) {
			for _, casing := range []string{"lowercase", "uppercase"} {
				t.Run(casing, func(t *testing.T) {
					db := migrationDB(t)
					seedOwnershipHost(t, db, "sqlite")
					upgradeExec(t, db, "sqlite", "CREATE TABLE host_changes (id INTEGER)")
					names := []string{"goauth_migrations", "audit_outbox", "idx_audit_outbox_claim", "archived_outbox", "idx_archived_outbox_claim"}
					for _, name := range names {
						if casing == "uppercase" {
							name = strings.ToUpper(name)
						}
						upgradeExec(t, db, "sqlite", "CREATE TRIGGER "+name+
							" AFTER UPDATE ON host_notes BEGIN INSERT INTO host_changes VALUES (NEW.id); END")
					}
					options := Options{Driver: "sqlite"}
					baseline := bootstrapCatalog(t, "sqlite")
					if _, err := runCatalog(t.Context(), db, options, baseline, "apply", 0); err != nil {
						t.Fatal("host trigger blocked fresh installation", err)
					}
					if _, err := runCatalog(t.Context(), db, options, baseline, "verify", 0); err != nil {
						t.Fatal("host trigger blocked current-schema verification", err)
					}
					upgradeExec(t, db, "sqlite", "DROP TABLE goauth_migrations")
					catalog := retirementCatalog(t, "sqlite", mode)
					adopted, err := runCatalog(t.Context(), db, options, catalog, "adopt", 1)
					if err != nil || adopted.Revision != 1 || len(adopted.History) != 1 || adopted.History[0].Mode != "adopted" {
						t.Fatalf("host trigger blocked baseline adoption: %+v, %v", adopted, err)
					}
					if _, err := runCatalog(t.Context(), db, options, catalog, "apply", 0); err != nil {
						t.Fatal("host trigger blocked retirement", err)
					}
					if _, err := runCatalog(t.Context(), db, options, catalog, "verify", 0); err != nil {
						t.Fatal("host trigger blocked retirement verification", err)
					}
					upgradeExec(t, db, "sqlite", "UPDATE host_notes SET id=id")
					var changes int
					if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM host_changes").Scan(&changes); err != nil || changes != len(names) {
						t.Fatal("host triggers were removed or stopped working", changes, err)
					}
					assertOwnershipHost(t, db)
				})
			}
		})
	}
}

func TestSQLiteCurrentNamesIgnoreASCIICaseAndRejectAuthTriggers(t *testing.T) {
	for _, names := range []struct{ name, table, claim, created string }{
		{"uppercase", "AUDIT_OUTBOX", "IDX_AUDIT_OUTBOX_CLAIM", "IDX_AUDIT_OUTBOX_CREATED_AT"},
		{"mixed case", "AuDiT_OuTbOx", "IdX_AuDiT_OuTbOx_ClAiM", "IdX_AuDiT_OuTbOx_CrEaTeD_At"},
	} {
		t.Run(names.name, func(t *testing.T) {
			db := migrationDB(t)
			catalog := bootstrapCatalog(t, "sqlite")
			rewrite := strings.NewReplacer("idx_audit_outbox_claim", names.claim,
				"idx_audit_outbox_created_at", names.created, "audit_outbox", names.table)
			for _, statement := range catalog.Migrations[0].statements {
				upgradeExec(t, db, "sqlite", rewrite.Replace(statement))
			}
			options := Options{Driver: "sqlite"}
			if _, err := runCatalog(t.Context(), db, options, catalog, "adopt", 1); err != nil {
				t.Fatal("identifier casing blocked baseline adoption", err)
			}
			for _, operation := range []string{"verify", "apply"} {
				if _, err := runCatalog(t.Context(), db, options, catalog, operation, 0); err != nil {
					t.Fatal("identifier casing blocked current-schema verification", operation, err)
				}
			}
			for _, trigger := range []string{"unexpected_auth_update", "UsErS", "IdX_UsErS_ApP_RoLe"} {
				upgradeExec(t, db, "sqlite", "CREATE TRIGGER "+trigger+" AFTER UPDATE ON "+names.table+" BEGIN SELECT 1; END")
				if _, err := runCatalog(t.Context(), db, options, catalog, "verify", 0); !errors.Is(err, ErrDrift) {
					t.Fatal("verification accepted a trigger attached to an auth table", trigger, err)
				}
				upgradeExec(t, db, "sqlite", "DROP TRIGGER "+trigger)
			}
		})
	}
}

func TestSQLiteNonASCIINameIsDistinct(t *testing.T) {
	db := migrationDB(t)
	// SQLite folds ASCII only; U+0130 is distinct from ASCII i.
	upgradeExec(t, db, "sqlite", "CREATE TABLE audİt_outbox (id INTEGER)")
	upgradeExec(t, db, "sqlite", "INSERT INTO audİt_outbox VALUES (42)")
	options := Options{Driver: "sqlite"}
	for _, catalog := range []Catalog{bootstrapCatalog(t, "sqlite"), retirementCatalog(t, "sqlite", "drop")} {
		for _, operation := range []string{"apply", "verify"} {
			if _, err := runCatalog(t.Context(), db, options, catalog, operation, 0); err != nil {
				t.Fatal("distinct non-ASCII host name was treated as an auth name", operation, err)
			}
		}
	}
	var id int
	if err := db.QueryRowContext(t.Context(), "SELECT id FROM audİt_outbox").Scan(&id); err != nil || id != 42 {
		t.Fatal("distinct non-ASCII host object changed", err)
	}
}
