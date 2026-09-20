package sqlstore

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
)

// TestClaimBatch_ConcurrentClaimersDeliverExactlyOnce proves that the
// guarded claim distributes each obligation to at most one of N concurrent
// claimers while every eligible obligation remains claimable by somebody.
func TestClaimBatch_ConcurrentClaimersDeliverExactlyOnce(t *testing.T) {
	const (
		claimerCount = 8
		eventCount   = 32
	)

	db := newAuditSQLiteDB(t)
	db.SetMaxOpenConns(claimerCount + 2)
	rec := NewRecordRepository(db)
	out := NewOutboxRepository(db)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < eventCount; i++ {
		id := fmt.Sprintf("10000000-0000-4000-8000-%012d", i)
		e := testEvent(id)
		seedEvent(t, rec, e)
		if err := out.Insert(ctx, e.ID, e.OrgID, audit.PriorityFor(e.Type), now); err != nil {
			t.Fatalf("seed outbox row %d: %v", i, err)
		}
	}

	start := make(chan struct{})
	claimed := make(chan []audit.OutboxRow, claimerCount)
	errs := make(chan error, claimerCount)
	var wg sync.WaitGroup
	for i := 0; i < claimerCount; i++ {
		owner := fmt.Sprintf("claimer-%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rows, err := out.ClaimBatch(ctx, owner, eventCount, time.Minute)
			if err != nil {
				errs <- err
				return
			}
			claimed <- rows
		}()
	}
	close(start)
	wg.Wait()
	close(claimed)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent claim: %v", err)
		}
	}

	seen := make(map[string]struct{}, eventCount)
	for rows := range claimed {
		for _, row := range rows {
			if _, duplicate := seen[row.EventID]; duplicate {
				t.Fatalf("event %q claimed more than once", row.EventID)
			}
			if row.Attempts != 1 {
				t.Fatalf("event %q attempts = %d, want 1", row.EventID, row.Attempts)
			}
			seen[row.EventID] = struct{}{}
		}
	}
	if len(seen) != eventCount {
		t.Fatalf("unique claimed events = %d, want %d", len(seen), eventCount)
	}
}
