package sqlstore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/port"
)

func recoveryRepositoryFixture(t *testing.T) (*DB, *RecoveryRepository) {
	t.Helper()
	raw := testdb.OpenSelected(t)
	testdb.Apply(t, raw)
	db := NewDB(raw, testdb.Driver(raw))
	return db, NewRecoveryRepository(db)
}

func TestRecoveryClaimIsExclusiveAndStaleCompletionCannotDeleteReclaimedJob(t *testing.T) {
	db, repo := recoveryRepositoryFixture(t)
	ctx := context.Background()
	if err := repo.Enqueue(ctx, port.RecoveryPasswordReset, "requested@example.com"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	start := make(chan struct{})
	results := make(chan *port.RecoveryRequest, 8)
	errChan := make(chan error, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			<-start
			request, err := repo.Claim(ctx, now, 2*time.Minute)
			results <- request
			errChan <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(errChan)
	for err := range errChan {
		if err != nil {
			t.Fatal(err)
		}
	}
	var winner *port.RecoveryRequest
	for request := range results {
		if request != nil {
			if winner != nil {
				t.Fatal("multiple workers claimed one live request")
			}
			winner = request
		}
	}
	if winner == nil || winner.Attempts != 1 {
		t.Fatalf("missing valid claim: %+v", winner)
	}
	reclaimed, err := repo.Claim(ctx, now.Add(2*time.Minute+time.Second), 2*time.Minute)
	if err != nil || reclaimed == nil || reclaimed.ID != winner.ID || reclaimed.Owner == winner.Owner || reclaimed.Attempts != 2 {
		t.Fatalf("expired claim not recovered: %+v, %v", reclaimed, err)
	}
	if err := repo.Complete(ctx, *winner, true, now); err != nil {
		t.Fatal(err)
	}
	if err := repo.Complete(ctx, *winner, false, now); err != nil {
		t.Fatal(err)
	}
	var owner string
	if err := db.QueryRow("SELECT claim_owner FROM recovery_requests").Scan(&owner); err != nil || owner != reclaimed.Owner {
		t.Fatalf("stale worker deleted or changed the current claim: %q, %v", owner, err)
	}
	if err := repo.Complete(ctx, *reclaimed, true, now); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRetryBudgetAndRetention(t *testing.T) {
	db, repo := recoveryRepositoryFixture(t)
	ctx := context.Background()
	if err := repo.Enqueue(ctx, port.RecoveryVerification, "requested@example.com"); err != nil {
		t.Fatal(err)
	}
	created := time.Now()
	now := created
	for attempt := 1; attempt <= 5; attempt++ {
		request, err := repo.Claim(ctx, now, 2*time.Minute)
		if err != nil || request == nil || request.Attempts != attempt {
			t.Fatalf("attempt %d: claim=%+v err=%v", attempt, request, err)
		}
		if err := repo.Complete(ctx, *request, false, now); err != nil {
			t.Fatal(err)
		}
		if next, err := repo.Claim(ctx, now, 2*time.Minute); err != nil || next != nil {
			t.Fatalf("retry ignored backoff: %+v, %v", next, err)
		}
		now = now.Add(5 * time.Minute)
	}
	if request, err := repo.Claim(ctx, now, 2*time.Minute); err != nil || request != nil {
		t.Fatalf("dead-lettered request remained eligible: %+v, %v", request, err)
	}
	var dead int
	if err := db.QueryRow("SELECT dead_lettered FROM recovery_requests").Scan(&dead); err != nil || dead != 1 {
		t.Fatalf("missing failure evidence: %d, %v", dead, err)
	}
	if err := repo.Enqueue(ctx, port.RecoveryPasswordReset, "old@example.com"); err != nil {
		t.Fatal(err)
	}
	if request, err := repo.Claim(ctx, created.Add(25*time.Hour), 2*time.Minute); err != nil || request != nil {
		t.Fatalf("stale request remained eligible: %+v, %v", request, err)
	}
	if err := repo.Prune(ctx, created.Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM recovery_requests").Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired requests retained: %d, %v", count, err)
	}
}
