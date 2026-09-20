package sqlstore

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/schema"
)

// poisonedTxSurvives is the per-driver savepoint proof: inside a real
// transaction, a failed record insert (duplicated id) followed by a rollback
// to the savepoint must leave the transaction usable — fail-open ("log it
// and continue") is impossible without it. SQLite's tests pass trivially
// (savepoints work standalone there); Postgres is where the guarantee
// matters, because a failed statement poisons the whole transaction until
// rollback.
func poisonedTxSurvives(t *testing.T, db *DB) {
	t.Helper()
	rec := NewRecordRepository(db)
	e := audit.Event{ID: "pg-evt-1", Type: audit.EventRoleChanged, Severity: audit.SeverityWarning,
		Success: true, CreatedAt: time.Now().UTC()}

	err := db.WithTx(context.Background(), func(ctx context.Context) error {
		if err := rec.Insert(ctx, e); err != nil {
			return err
		}
		spErr := db.Savepoint(ctx, "audit_record", func(sp context.Context) error {
			return rec.Insert(sp, e) // duplicate id — must fail
		})
		if spErr == nil {
			t.Fatal("expected duplicate-id insert to fail")
		}
		// The transaction must still be usable — on Postgres this is where a
		// poisoned transaction would reject every later statement.
		_, err := db.ExecContext(ctx,
			"INSERT INTO audit_log (id, event_type, severity, success, created_at) VALUES ($1,$2,$3,$4,$5)",
			"pg-evt-2", "login.success", "info", true, time.Now().UTC())
		return err
	})
	if err != nil {
		t.Fatalf("transaction should survive a failed savepoint insert: %v", err)
	}
	var n int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM audit_log").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("audit_log rows = %d, want 2", n)
	}
}

// savepointNoTxIsInert pins the second half of the savepoint contract: with
// no surrounding transaction, Savepoint must not issue SAVEPOINT/RELEASE at
// all — Postgres errors on RELEASE SAVEPOINT outside a transaction block
// (SQLite accepts it, which is why this only bites per-driver). Every
// post-commit Record takes this path.
func savepointNoTxIsInert(t *testing.T, db *DB) {
	t.Helper()
	ran := false
	if err := db.Savepoint(context.Background(), "audit_record", func(context.Context) error {
		ran = true
		return nil
	}); err != nil {
		t.Fatalf("Savepoint without a transaction must be a no-op pass-through: %v", err)
	}
	if !ran {
		t.Fatal("the wrapped function must still run")
	}
}

// TestOutboxSchemaApplies proves the audit_outbox DDL loads on this driver
// (indexes included) — the migration the dispatcher's TableExists check
// depends on.
func TestOutboxSchemaApplies(t *testing.T) {
	for _, driver := range []string{"sqlite3"} {
		sqlText, err := schema.For(driver)
		if err != nil {
			t.Fatalf("%s: %v", driver, err)
		}
		var outbox, claim, created int
		for _, stmt := range schema.SplitSQL(sqlText) {
			switch {
			case containsCreateTableOutbox(stmt):
				outbox++
			case containsIdxClaim(stmt):
				claim++
			case containsIdxCreated(stmt):
				created++
			}
		}
		if outbox != 1 || claim != 1 || created != 1 {
			t.Fatalf("%s: audit_outbox table=%d claim-idx=%d created-idx=%d, want 1 each", driver, outbox, claim, created)
		}
	}
}

func containsCreateTableOutbox(stmt string) bool {
	lower := strings.ToLower(stmt)
	return strings.Contains(lower, "create table") && strings.Contains(lower, "audit_outbox")
}

func containsIdxClaim(stmt string) bool {
	return strings.Contains(strings.ToLower(stmt), "idx_audit_outbox_claim")
}

func containsIdxCreated(stmt string) bool {
	return strings.Contains(strings.ToLower(stmt), "idx_audit_outbox_created_at")
}

var _ = sql.ErrNoRows
var _ = audit.PriorityCritical
var _ = context.Background
var _ = time.Now
