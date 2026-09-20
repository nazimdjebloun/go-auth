package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/schema"
)

// newAuditSQLiteDB applies the real embedded schema (including audit_outbox)
// to a temp SQLite file, so the tests exercise the actual DDL.
func newAuditSQLiteDB(t *testing.T) *DB {
	t.Helper()
	f, err := os.CreateTemp("", "goauth-outbox-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", f.Name()+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = raw.Close()
		_ = os.Remove(f.Name())
	})

	schemaSQL, err := schema.For("sqlite3")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schema.SplitSQL(schemaSQL) {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("schema exec: %v", err)
		}
	}
	return NewDB(raw, "sqlite")
}

func seedEvent(t *testing.T, rec *RecordRepository, e audit.Event) {
	t.Helper()
	if err := rec.Insert(context.Background(), e); err != nil {
		t.Fatalf("seed record: %v", err)
	}
}

func testEvent(id string) audit.Event {
	org := "org-1"
	return audit.Event{ID: id, Type: audit.EventRoleChanged, Severity: audit.SeverityWarning,
		Success: true, OrgID: &org, CreatedAt: time.Now().UTC()}
}

func countRows(t *testing.T, db *DB, table string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRecordIffCommit is the invariant the whole design exists for: the
// record (and its delivery obligation) exists iff the surrounding
// transaction commits. A rollback discards both; neither survives alone.
func TestRecordIffCommit(t *testing.T) {
	db := newAuditSQLiteDB(t)
	rec := NewRecordRepository(db)
	out := NewOutboxRepository(db)
	ctx := context.Background()

	// Rollback case: the state change fails, so the record and the
	// obligation must vanish with it.
	err := db.WithTx(ctx, func(ctx context.Context) error {
		e := testEvent("rollback-event")
		if err := rec.Insert(ctx, e); err != nil {
			return err
		}
		if err := out.Insert(ctx, e.ID, e.OrgID, audit.PriorityFor(e.Type), time.Now().UTC()); err != nil {
			return err
		}
		return errors.New("force rollback")
	})
	if err == nil {
		t.Fatal("expected forced rollback")
	}
	if n := countRows(t, db, "audit_log"); n != 0 {
		t.Fatalf("after rollback: audit_log rows = %d, want 0", n)
	}
	if n := countRows(t, db, "audit_outbox"); n != 0 {
		t.Fatalf("after rollback: audit_outbox rows = %d, want 0 (no orphaned obligation)", n)
	}

	// Commit case: both persist together.
	err = db.WithTx(ctx, func(ctx context.Context) error {
		e := testEvent("evt-commit")
		if err := rec.Insert(ctx, e); err != nil {
			return err
		}
		return out.Insert(ctx, e.ID, e.OrgID, audit.PriorityFor(e.Type), time.Now().UTC())
	})
	if err != nil {
		t.Fatalf("commit case: %v", err)
	}
	if countRows(t, db, "audit_log") != 1 || countRows(t, db, "audit_outbox") != 1 {
		t.Fatalf("after commit: records=%d outbox=%d, want 1 and 1",
			countRows(t, db, "audit_log"), countRows(t, db, "audit_outbox"))
	}
}

// TestSavepoint_FailedInsertKeepsTxUsable: a failed statement inside a
// savepoint must not poison the surrounding transaction — fail-open ("log
// it and continue") is impossible without SAVEPOINT / ROLLBACK TO SAVEPOINT.
func TestSavepoint_FailedInsertKeepsTxUsable(t *testing.T) {
	db := newAuditSQLiteDB(t)
	rec := NewRecordRepository(db)

	e := testEvent("evt-1")
	err := db.WithTx(context.Background(), func(ctx context.Context) error {
		// First insert succeeds inside the tx.
		if err := rec.Insert(ctx, e); err != nil {
			return err
		}
		// Second insert with the same id fails (PK violation) — under a
		// poisoned transaction every later statement would error. The
		// savepoint rollback must restore the tx to a usable state.
		spErr := db.Savepoint(ctx, "audit_record", func(sp context.Context) error {
			return rec.Insert(sp, e) // PK violation
		})
		if spErr == nil {
			t.Fatal("expected duplicate-id insert to fail")
		}
		// The tx is still usable: a later statement must succeed.
		_, err := db.ExecContext(ctx,
			"INSERT INTO audit_log (id, event_type, severity, success, created_at) VALUES ($1,$2,$3,$4,$5)",
			"evt-2", "login.success", "info", true, time.Now().UTC())
		return err
	})
	if err != nil {
		t.Fatalf("transaction should survive a failed savepoint insert: %v", err)
	}
	if countRows(t, db, "audit_log") != 2 {
		t.Fatalf("audit_log rows = %d, want 2", countRows(t, db, "audit_log"))
	}
}

// TestClaimBatch_LeaseAndSteal covers the guarded CAS claim: a live claim
// blocks other claimers, an expired lease is stealable (flagged as a benign
// duplicate), and success deletes only the obligation.
func TestClaimBatch_LeaseAndSteal(t *testing.T) {
	db := newAuditSQLiteDB(t)
	rec := NewRecordRepository(db)
	out := NewOutboxRepository(db)
	ctx := context.Background()

	e := testEvent("evt-claim")
	seedEvent(t, rec, e)
	if err := out.Insert(ctx, e.ID, e.OrgID, audit.PriorityFor(e.Type), time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	const lease = time.Minute
	rows, err := out.ClaimBatch(ctx, "owner-a", 10, lease)
	if err != nil || len(rows) != 1 {
		t.Fatalf("first claim: rows=%d err=%v", len(rows), err)
	}
	if rows[0].Stolen {
		t.Error("fresh claim must not be flagged stolen")
	}
	if rows[0].Event.ID != e.ID || rows[0].Event.Type != audit.EventRoleChanged {
		t.Fatalf("claimed event not rebuilt correctly: %+v", rows[0].Event)
	}
	if rows[0].Attempts != 1 {
		t.Fatalf("attempts after claim = %d, want 1", rows[0].Attempts)
	}
	var claimToken string
	if err := db.QueryRowContext(ctx,
		"SELECT claim_owner FROM audit_outbox WHERE audit_log_id = $1", e.ID).
		Scan(&claimToken); err != nil {
		t.Fatal(err)
	}
	if claimToken == "owner-a" || !strings.HasPrefix(claimToken, "owner-a:") {
		t.Fatalf("claim_owner = %q, want unique token prefixed by owner-a", claimToken)
	}

	// A live claim by another instance must see nothing.
	again, err := out.ClaimBatch(ctx, "owner-b", 10, lease)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Fatalf("second claim stole a live lease: got %d rows", len(again))
	}

	// Expire the lease: the row becomes claimable again and the steal is
	// flagged (a benign duplicate under at-least-once delivery).
	if _, err := db.ExecContext(ctx,
		"UPDATE audit_outbox SET claimed_at = $1 WHERE audit_log_id = $2",
		time.Now().UTC().Add(-2*lease), e.ID); err != nil {
		t.Fatal(err)
	}
	stolen, err := out.ClaimBatch(ctx, "owner-b", 10, lease)
	if err != nil || len(stolen) != 1 {
		t.Fatalf("steal claim: rows=%d err=%v", len(stolen), err)
	}
	if !stolen[0].Stolen {
		t.Error("stolen claim must be flagged so the dispatcher counts the duplicate")
	}

	// Success deletes the obligation — the row's existence was the pending state.
	if err := out.MarkSuccess(ctx, rows[0].EventID); err != nil {
		t.Fatal(err)
	}
	if countRows(t, db, "audit_outbox") != 0 {
		t.Fatal("obligation should be deleted on success")
	}
	// The record is untouched by delivery bookkeeping.
	if countRows(t, db, "audit_log") != 1 {
		t.Fatal("record must survive delivery")
	}
}

func TestRetryThenDeadLetter(t *testing.T) {
	db := newAuditSQLiteDB(t)
	rec := NewRecordRepository(db)
	out := NewOutboxRepository(db)
	ctx := context.Background()

	e := testEvent("evt-retry")
	seedEvent(t, rec, e)
	if err := out.Insert(ctx, e.ID, e.OrgID, 0, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	rows, err := out.ClaimBatch(ctx, "w1", 10, time.Minute)
	if err != nil || len(rows) != 1 {
		t.Fatalf("claim: rows=%d err=%v", len(rows), err)
	}

	// Failure before MaxAttempts: scheduled for retry, claim released.
	if err := out.MarkFailure(ctx, rows[0].EventID, time.Now().UTC().Add(time.Minute), "boom"); err != nil {
		t.Fatal(err)
	}
	var attempts int
	var nextAttempt time.Time
	if err := db.QueryRowContext(ctx,
		"SELECT attempts, next_attempt_at FROM audit_outbox WHERE audit_log_id = $1", e.ID).
		Scan(&attempts, &nextAttempt); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
	if time.Until(nextAttempt) <= 0 {
		t.Fatal("next_attempt_at must be in the future after a failure")
	}

	// Terminal failure: dead-lettered, not deleted — evidence survives.
	if err := out.MarkDeadLetter(ctx, rows[0].EventID, time.Now().UTC(), "still boom"); err != nil {
		t.Fatal(err)
	}
	var deadLetter sql.NullTime
	if err := db.QueryRowContext(ctx,
		"SELECT dead_lettered_at FROM audit_outbox WHERE audit_log_id = $1", e.ID).
		Scan(&deadLetter); err != nil {
		t.Fatal(err)
	}
	if !deadLetter.Valid {
		t.Fatal("dead_lettered_at must be set after a terminal failure")
	}
	if countRows(t, db, "audit_log") != 1 {
		t.Fatal("dead-lettering must never touch the record")
	}
}

func TestSweepEvictOrphan(t *testing.T) {
	db := newAuditSQLiteDB(t)
	rec := NewRecordRepository(db)
	out := NewOutboxRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// Pending row past OutboxMaxAge → pendingEvicted.
	old := testEvent("evt-old")
	seedEvent(t, rec, old)
	_ = out.Insert(ctx, old.ID, old.OrgID, 0, now.Add(-8*24*time.Hour))

	// Dead-lettered row past DeadLetterTTL → deadPurged.
	dead := testEvent("evt-dead")
	seedEvent(t, rec, dead)
	_ = out.Insert(ctx, dead.ID, dead.OrgID, 0, now.Add(-24*time.Hour))
	_, _ = db.ExecContext(ctx, "UPDATE audit_outbox SET dead_lettered_at = $1 WHERE audit_log_id = $2",
		now.Add(-8*24*time.Hour), dead.ID)

	// Orphan: obligation without a record (simulates a broken invariant).
	if _, err := db.ExecContext(ctx,
		"INSERT INTO audit_outbox (audit_log_id, org_id, priority, next_attempt_at, created_at) VALUES ($1,$2,0,$3,$4)",
		"orphan-id", nil, now, now); err != nil {
		t.Fatal(err)
	}

	pendingEvicted, deadPurged, err := out.SweepExpired(ctx, now, 7*24*time.Hour, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if pendingEvicted != 1 || deadPurged != 1 {
		t.Fatalf("sweep: pendingEvicted=%d deadPurged=%d, want 1 and 1", pendingEvicted, deadPurged)
	}
	// Eviction never touches the records.
	if countRows(t, db, "audit_log") != 2 {
		t.Fatalf("audit_log rows = %d, want 2 (sweep never touches records)", countRows(t, db, "audit_log"))
	}
	// The fresh orphan row survives the age sweep.
	if countRows(t, db, "audit_outbox") != 1 {
		t.Fatalf("audit_outbox rows after sweep = %d, want 1 (orphan survives the age sweep)", countRows(t, db, "audit_outbox"))
	}

	orphans, err := out.PurgeOrphans(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if orphans != 1 {
		t.Fatalf("orphans purged = %d, want 1", orphans)
	}
	if countRows(t, db, "audit_outbox") != 0 {
		t.Fatalf("audit_outbox rows after purge = %d, want 0", countRows(t, db, "audit_outbox"))
	}
}

func TestEvictOverCap_DeadLettersFirst(t *testing.T) {
	db := newAuditSQLiteDB(t)
	rec := NewRecordRepository(db)
	out := NewOutboxRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	// 2 pending + 2 dead-lettered; cap 3 → one dead letter shed first.
	for _, id := range []string{"p1", "p2", "d1", "d2"} {
		e := testEvent(id)
		seedEvent(t, rec, e)
		_ = out.Insert(ctx, e.ID, e.OrgID, 0, now)
		if id[0] == 'd' {
			_, _ = db.ExecContext(ctx, "UPDATE audit_outbox SET dead_lettered_at = $1 WHERE audit_log_id = $2", now, e.ID)
		}
	}

	evicted, pendingEvicted, err := out.EvictOverCap(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if evicted != 1 || pendingEvicted != 0 {
		t.Fatalf("evict: evicted=%d pendingEvicted=%d, want 1 and 0 (dead letters shed first)", evicted, pendingEvicted)
	}
	// Eviction never touches audit_log.
	if countRows(t, db, "audit_log") != 4 {
		t.Fatalf("audit_log rows = %d, want 4 (cap eviction never touches records)", countRows(t, db, "audit_log"))
	}

	// Push past the dead-letter supply: pending rows get shed and reported.
	evicted, pendingEvicted, err = out.EvictOverCap(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if evicted != 2 || pendingEvicted != 1 {
		t.Fatalf("second evict: evicted=%d pendingEvicted=%d, want 2 and 1 (one dead letter left, both pending shed)", evicted, pendingEvicted)
	}
}
