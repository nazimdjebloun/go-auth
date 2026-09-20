package integration_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
)

func utcNow() time.Time { return time.Now().UTC() }

func leaseMinute() time.Duration { return time.Minute }

func dbCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func testOnlyError() error { return errors.New("integration: force rollback") }

func day() time.Duration { return 24 * time.Hour }

// poisonedTxSurvives is the savepoint proof used by both driver suites: a
// failed record insert (duplicated id) followed by a rollback-to-savepoint
// must leave the transaction usable, on whatever driver it runs against.
func poisonedTxSurvives(t *testing.T, db *sqlstore.DB) {
	t.Helper()
	rec := sqlstore.NewRecordRepository(db)
	e := audit.Event{ID: "00000000-0000-4000-8000-000000000001", Type: audit.EventRoleChanged, Severity: audit.SeverityWarning,
		Success: true, CreatedAt: utcNow()}

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
		// The transaction must still be usable: on Postgres a poisoned
		// transaction would reject every later statement here; on MySQL the
		// savepoint rollback restores the statement state it checkpoints.
		_, err := db.ExecContext(ctx,
			"INSERT INTO audit_log (id, event_type, severity, success, created_at) VALUES ($1,$2,$3,$4,$5)",
			"00000000-0000-4000-8000-000000000002", "login.success", "info", true, utcNow())
		return err
	})
	if err != nil {
		t.Fatalf("transaction should survive a failed savepoint insert: %v", err)
	}
}

var _ = goauth.DriverPostgres
