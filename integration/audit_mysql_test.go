package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
)

// TestMySQL_AuditPoisonedTxSurvives is the per-driver twin of the Postgres
// savepoint proof: a failed record insert inside a transaction must leave
// the transaction usable under fail-open. This is also the driver that
// proves savepoint semantics are portable — not assumed from the Postgres
// result.
func TestMySQL_AuditPoisonedTxSurvives(t *testing.T) {
	dsn := mysqlTestDSN()
	if dsn == "" {
		t.Skip("GOAUTH_MYSQL_TEST_DSN not set")
	}

	db, cleanup := mysqlTestDB(t, dsn)
	defer cleanup()
	migrateDB(t, db, "mysql")

	wrapped := sqlstore.NewDB(db, "mysql")
	poisonedTxSurvives(t, wrapped)
}

// TestMySQL_AuditEmergencyValveEvicts is the regression test for the MySQL
// incompatibility the design review flagged: DELETE ... WHERE id IN
// (SELECT ... LIMIT n) is rejected by MySQL (ERROR 1235), which would leave
// the emergency valve erroring every janitor tick and the outbox growing
// unbounded. EvictOverCap selects candidates then deletes by id — this test
// exercises exactly that on the driver that forbids the single-statement
// form.
func TestMySQL_AuditEmergencyValveEvicts(t *testing.T) {
	dsn := mysqlTestDSN()
	if dsn == "" {
		t.Skip("GOAUTH_MYSQL_TEST_DSN not set")
	}

	db, cleanup := mysqlTestDB(t, dsn)
	defer cleanup()
	migrateDB(t, db, "mysql")

	wrapped := sqlstore.NewDB(db, "mysql")
	rec := sqlstore.NewRecordRepository(wrapped)
	out := sqlstore.NewOutboxRepository(wrapped)
	ctx := context.Background()

	// 2 pending + 2 dead-lettered; cap 3 must shed one dead letter first.
	for _, tc := range []struct {
		id         string
		deadLetter bool
	}{
		{id: "my-p1"},
		{id: "my-p2"},
		{id: "my-d1", deadLetter: true},
		{id: "my-d2", deadLetter: true},
	} {
		e := audit.Event{ID: tc.id, Type: audit.EventLoginFailed, Severity: audit.SeverityWarning, CreatedAt: utcNow()}
		if err := rec.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
		if err := out.Insert(ctx, e.ID, nil, audit.PriorityFor(e.Type), utcNow()); err != nil {
			t.Fatal(err)
		}
		if tc.deadLetter {
			if err := out.MarkDeadLetter(ctx, e.ID, utcNow(), "down"); err != nil {
				t.Fatal(err)
			}
		}
	}

	evicted, pending, err := out.EvictOverCap(ctx, 3)
	if err != nil {
		t.Fatalf("emergency valve must work on MySQL: %v", err)
	}
	if evicted != 1 || pending != 0 {
		t.Fatalf("evict: evicted=%d pending=%d, want 1 and 0 (dead letters shed first)", evicted, pending)
	}
	if n := dbCount(t, db, "SELECT COUNT(*) FROM audit_log"); n != 4 {
		t.Fatalf("audit_log = %d, want 4 — eviction must never touch records", n)
	}
}

// TestMySQL_AuditClaimBatchRoundTrip catches timestamp-precision regressions
// in the claim path. MySQL may normalize DATETIME values when they are stored,
// so ClaimBatch must identify the rows it won without relying on an exact
// round-trip comparison against the caller's time.Time value.
func TestMySQL_AuditClaimBatchRoundTrip(t *testing.T) {
	dsn := mysqlTestDSN()
	if dsn == "" {
		t.Skip("GOAUTH_MYSQL_TEST_DSN not set")
	}

	db, cleanup := mysqlTestDB(t, dsn)
	defer cleanup()
	migrateDB(t, db, "mysql")

	wrapped := sqlstore.NewDB(db, "mysql")
	rec := sqlstore.NewRecordRepository(wrapped)
	out := sqlstore.NewOutboxRepository(wrapped)
	ctx := context.Background()

	const eventID = "my-claim-round-trip"
	e := audit.Event{
		ID:        eventID,
		Type:      audit.EventRoleChanged,
		Severity:  audit.SeverityWarning,
		Success:   true,
		CreatedAt: utcNow(),
	}
	if err := rec.Insert(ctx, e); err != nil {
		t.Fatal(err)
	}
	if err := out.Insert(ctx, e.ID, nil, audit.PriorityFor(e.Type), utcNow()); err != nil {
		t.Fatal(err)
	}

	rows, err := out.ClaimBatch(ctx, "mysql-round-trip", 1, leaseMinute())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].EventID != eventID {
		t.Fatalf("claimed rows = %+v, want exactly %q", rows, eventID)
	}
}

// TestMySQL_AuditSweepExpired exercises the two outbox clocks on this
// driver: pending rows past OutboxMaxAge are evicted (delivery abandoned,
// record intact), dead-lettered rows past DeadLetterTTL are purged.
func TestMySQL_AuditSweepExpired(t *testing.T) {
	dsn := mysqlTestDSN()
	if dsn == "" {
		t.Skip("GOAUTH_MYSQL_TEST_DSN not set")
	}

	db, cleanup := mysqlTestDB(t, dsn)
	defer cleanup()
	migrateDB(t, db, "mysql")

	wrapped := sqlstore.NewDB(db, "mysql")
	rec := sqlstore.NewRecordRepository(wrapped)
	out := sqlstore.NewOutboxRepository(wrapped)
	ctx := context.Background()
	now := utcNow()

	old := audit.Event{ID: "my-old", Type: audit.EventRoleChanged, Severity: audit.SeverityWarning,
		Success: true, CreatedAt: now.Add(-8 * day())}
	if err := rec.Insert(ctx, old); err != nil {
		t.Fatal(err)
	}
	if err := out.Insert(ctx, old.ID, old.OrgID, 0, now.Add(-8*day())); err != nil {
		t.Fatal(err)
	}

	dead := audit.Event{ID: "my-dead", Type: audit.EventRoleChanged, Severity: audit.SeverityWarning,
		Success: true, CreatedAt: now.Add(-time.Hour)}
	if err := rec.Insert(ctx, dead); err != nil {
		t.Fatal(err)
	}
	if err := out.Insert(ctx, dead.ID, dead.OrgID, 0, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE audit_outbox SET dead_lettered_at = ? WHERE audit_log_id = ?",
		now.Add(-8*day()).Format("2006-01-02 15:04:05"), dead.ID); err != nil {
		t.Fatal(err)
	}

	pendingEvicted, deadPurged, err := out.SweepExpired(ctx, now, 7*day(), 7*day())
	if err != nil {
		t.Fatal(err)
	}
	if pendingEvicted != 1 || deadPurged != 1 {
		t.Fatalf("sweep: pendingEvicted=%d deadPurged=%d, want 1 and 1", pendingEvicted, deadPurged)
	}
	if n := dbCount(t, db, "SELECT COUNT(*) FROM audit_log"); n != 2 {
		t.Fatalf("audit_log = %d, want 2 — sweep must never touch records", n)
	}
}
