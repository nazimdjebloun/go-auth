package integration_test

import (
	"context"
	"os"
	"testing"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
)

// TestPostgres_AuditRecordIffCommit exercises the invariant the design exists
// for, on this driver: the record and its delivery obligation are written in
// the caller's transaction, so a rollback discards both and a commit keeps
// both. It uses the repository layer directly so the assertion is about
// transactional atomicity, not about any one service path.
func TestPostgres_AuditRecordIffCommit(t *testing.T) {
	dsn := os.Getenv("GOAUTH_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_POSTGRES_DSN not set")
	}

	db, cleanup := postgresTestDB(t, dsn)
	defer cleanup()
	migrateDB(t, db, "postgres")

	wrapped := sqlstore.NewDB(db, "postgres")
	rec := sqlstore.NewRecordRepository(wrapped)
	out := sqlstore.NewOutboxRepository(wrapped)
	ctx := context.Background()

	writeBoth := func(ctx context.Context, id string) error {
		e := audit.Event{ID: id, Type: audit.EventRoleChanged, Severity: audit.SeverityWarning,
			Success: true, CreatedAt: utcNow()}
		if err := rec.Insert(ctx, e); err != nil {
			return err
		}
		return out.Insert(ctx, e.ID, e.OrgID, audit.PriorityFor(e.Type), utcNow())
	}

	rolledBack := testOnlyError()
	if err := wrapped.WithTx(ctx, func(txCtx context.Context) error {
		if err := writeBoth(txCtx, "00000000-0000-4000-8000-000000000011"); err != nil {
			return err
		}
		return rolledBack
	}); err != rolledBack {
		t.Fatalf("expected forced rollback, got %v", err)
	}
	if n := dbCount(t, db, "SELECT COUNT(*) FROM audit_log"); n != 0 {
		t.Fatalf("after rollback: audit_log = %d, want 0", n)
	}
	if n := dbCount(t, db, "SELECT COUNT(*) FROM audit_outbox"); n != 0 {
		t.Fatalf("after rollback: audit_outbox = %d, want 0", n)
	}

	if err := wrapped.WithTx(ctx, func(txCtx context.Context) error {
		return writeBoth(txCtx, "00000000-0000-4000-8000-000000000012")
	}); err != nil {
		t.Fatalf("commit case: %v", err)
	}
	if n := dbCount(t, db, "SELECT COUNT(*) FROM audit_log"); n != 1 {
		t.Fatalf("after commit: audit_log = %d, want 1", n)
	}
	if n := dbCount(t, db, "SELECT COUNT(*) FROM audit_outbox"); n != 1 {
		t.Fatalf("after commit: audit_outbox = %d, want 1", n)
	}
}

// TestPostgres_AuditPoisonedTxSurvives proves the savepoint behavior fail-open
// depends on, on this driver: a failed record insert inside a transaction does
// not poison the transaction — the surrounding work still commits. On
// Postgres a failed statement rejects every later statement until a savepoint
// rollback, so this is the driver where the guarantee actually bites.
func TestPostgres_AuditPoisonedTxSurvives(t *testing.T) {
	dsn := os.Getenv("GOAUTH_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_POSTGRES_DSN not set")
	}

	db, cleanup := postgresTestDB(t, dsn)
	defer cleanup()
	migrateDB(t, db, "postgres")

	wrapped := sqlstore.NewDB(db, "postgres")
	poisonedTxSurvives(t, wrapped)
}

// TestPostgres_AuditSavepointNoTxIsInert pins the post-commit path: every
// Record outside a transaction must not issue SAVEPOINT/RELEASE — Postgres
// errors on RELEASE SAVEPOINT outside a transaction block, where SQLite
// (where these tests also run) accepts it. This is the regression the
// inert-savepoint short-circuit exists for.
func TestPostgres_AuditSavepointNoTxIsInert(t *testing.T) {
	dsn := os.Getenv("GOAUTH_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_POSTGRES_DSN not set")
	}

	db, cleanup := postgresTestDB(t, dsn)
	defer cleanup()
	migrateDB(t, db, "postgres")

	wrapped := sqlstore.NewDB(db, "postgres")
	if err := wrapped.Savepoint(context.Background(), "audit_record", func(context.Context) error {
		return nil
	}); err != nil {
		t.Fatalf("Savepoint without a transaction must be a no-op pass-through: %v", err)
	}
}

// TestPostgres_AuditClaimAndEvict covers the guarded CAS claim and the
// select-then-delete emergency valve on this driver. ClaimBatch returns
// nothing while a lease is live.
func TestPostgres_AuditClaimAndEvict(t *testing.T) {
	dsn := os.Getenv("GOAUTH_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_POSTGRES_DSN not set")
	}

	db, cleanup := postgresTestDB(t, dsn)
	defer cleanup()
	migrateDB(t, db, "postgres")

	wrapped := sqlstore.NewDB(db, "postgres")
	rec := sqlstore.NewRecordRepository(wrapped)
	out := sqlstore.NewOutboxRepository(wrapped)
	ctx := context.Background()

	ids := []string{
		"00000000-0000-4000-8000-000000000021",
		"00000000-0000-4000-8000-000000000022",
	}
	for _, id := range ids {
		e := audit.Event{ID: id, Type: audit.EventLoginFailed, Severity: audit.SeverityWarning, CreatedAt: utcNow()}
		if err := rec.Insert(ctx, e); err != nil {
			t.Fatal(err)
		}
		if err := out.Insert(ctx, e.ID, nil, audit.PriorityFor(e.Type), utcNow()); err != nil {
			t.Fatal(err)
		}
	}

	rows, err := out.ClaimBatch(ctx, "pg-owner", 10, leaseMinute())
	if err != nil || len(rows) != 2 {
		t.Fatalf("claim: rows=%d err=%v", len(rows), err)
	}
	if rows[0].Event.Type != audit.EventLoginFailed {
		t.Fatalf("claimed event type = %v, want login.failed", rows[0].Event.Type)
	}

	// Second claim while the lease is live must see nothing.
	again, err := out.ClaimBatch(ctx, "pg-other", 10, leaseMinute())
	if err != nil || len(again) != 0 {
		t.Fatalf("second claim: rows=%d err=%v — must not steal a live lease", len(again), err)
	}

	// The emergency valve sheds dead letters first and deletes by id.
	for _, id := range ids {
		if err := out.MarkDeadLetter(ctx, id, utcNow(), "down"); err != nil {
			t.Fatal(err)
		}
	}
	evicted, pending, err := out.EvictOverCap(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if evicted != 1 || pending != 0 {
		t.Fatalf("evict: evicted=%d pending=%d, want 1 and 0", evicted, pending)
	}
	if n := dbCount(t, db, "SELECT COUNT(*) FROM audit_log"); n != 2 {
		t.Fatalf("audit_log = %d, want 2 — eviction must never touch records", n)
	}
}
