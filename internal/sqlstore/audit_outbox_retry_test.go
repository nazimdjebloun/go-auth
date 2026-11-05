package sqlstore

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

func TestClaimBatch_StaleCandidateRespectsRetryDeadline(t *testing.T) {
	raw := testdb.OpenSelected(t)
	testdb.Apply(t, raw)
	db := NewDB(raw, testdb.Driver(raw))
	rec := NewRecordRepository(db)
	out := NewOutboxRepository(db)
	ctx := context.Background()
	const lease = time.Minute
	now := time.Now().UTC()
	e := testEvent("20000000-0000-4000-8000-000000000001")
	e.OrgID = nil
	seedEvent(t, rec, e)
	if err := out.Insert(ctx, e.ID, e.OrgID, audit.PriorityFor(e.Type), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	// Pause a slow claimer after selection, before its guarded UPDATE.
	var candidateID string
	var wasClaimed int
	if err := db.QueryRowContext(ctx, outboxCandidates, now, now.Add(-lease), 1).
		Scan(&candidateID, &wasClaimed); err != nil {
		t.Fatal(err)
	}
	if candidateID != e.ID || wasClaimed != 0 {
		t.Fatalf("candidate = (%q, %d), want (%q, 0)", candidateID, wasClaimed, e.ID)
	}

	// Another claimer delivers, fails, and releases the claim with backoff.
	rows, err := out.ClaimBatch(ctx, "fast", 1, lease)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Attempts != 1 {
		t.Fatalf("first claim = %+v, want one row at attempt 1", rows)
	}
	nextAttempt := now.Add(time.Hour).Truncate(time.Second)
	if err := out.MarkFailure(ctx, e.ID, nextAttempt, "sink unavailable"); err != nil {
		t.Fatal(err)
	}

	// Resume the slow claimer using its stale candidate. It must not consume
	// another attempt before the newly scheduled retry deadline.
	claimTime := time.Now().UTC()
	result, err := db.ExecContext(ctx, outboxClaimCAS, claimTime, "slow:stale", candidateID, now.Add(-lease), claimTime)
	if err != nil {
		t.Fatal(err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("stale claim affected %d rows before retry deadline, want 0", n)
	}

	var attempts int
	var claimOwner string
	var claimedAt sql.NullTime
	var persistedDeadline time.Time
	if err := db.QueryRowContext(ctx,
		"SELECT attempts, claim_owner, claimed_at, next_attempt_at FROM audit_outbox WHERE audit_log_id = $1", e.ID).
		Scan(&attempts, &claimOwner, &claimedAt, &persistedDeadline); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || claimOwner != "" || claimedAt.Valid || !persistedDeadline.Equal(nextAttempt) {
		t.Fatalf("retry changed: attempts=%d, owner=%q, claimed=%v, deadline=%v", attempts, claimOwner, claimedAt, persistedDeadline)
	}
	rows, err = out.ClaimBatch(ctx, "early", 1, lease)
	if err != nil || len(rows) != 0 {
		t.Fatalf("early claim = %+v, %v; want no rows", rows, err)
	}

	// Advance eligibility without sleeping; the next legitimate claim uses
	// attempt 2, and successful delivery preserves the primary audit record.
	if _, err := db.ExecContext(ctx,
		"UPDATE audit_outbox SET next_attempt_at = $1 WHERE audit_log_id = $2", now.Add(-time.Minute), e.ID); err != nil {
		t.Fatal(err)
	}
	rows, err = out.ClaimBatch(ctx, "retry", 1, lease)
	if err != nil || len(rows) != 1 || rows[0].Attempts != 2 {
		t.Fatalf("retry claim = %+v, %v; want one row at attempt 2", rows, err)
	}
	if err := out.MarkSuccess(ctx, e.ID); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, db, "audit_outbox"); n != 0 {
		t.Fatalf("outbox rows = %d, want 0", n)
	}
	if n := countRows(t, db, "audit_log"); n != 1 {
		t.Fatalf("audit records = %d, want 1", n)
	}
}
