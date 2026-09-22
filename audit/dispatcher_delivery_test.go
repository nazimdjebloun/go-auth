package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type liveStealOutbox struct {
	fakeOutbox

	claimMu sync.Mutex
	claims  int
	event   OutboxRow
}

func (o *liveStealOutbox) ClaimBatch(context.Context, string, int, time.Duration) ([]OutboxRow, error) {
	o.claimMu.Lock()
	defer o.claimMu.Unlock()

	o.claims++
	switch o.claims {
	case 1:
		row := o.event
		row.Attempts = 1
		return []OutboxRow{row}, nil
	case 2:
		row := o.event
		row.Attempts = 2
		row.Stolen = true
		return []OutboxRow{row}, nil
	default:
		return nil, nil
	}
}

// TestDispatchOnce_LiveLeaseStealIsDedupedAtReceiver exercises the complete
// at-least-once boundary. The original claimer remains blocked in a webhook
// receiver while another dispatcher receives the same row as a lease steal.
// Both HTTP deliveries arrive, but the receiver applies the event once by
// atomically deduplicating on Event.ID, and the dispatcher counts the steal.
func TestDispatchOnce_LiveLeaseStealIsDedupedAtReceiver(t *testing.T) {
	row := claimable("lease-steal-event", 1)
	outbox := &liveStealOutbox{event: row}

	firstReceived := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }

	var requests atomic.Int32
	var receiverMu sync.Mutex
	received := make(map[string]struct{})
	applied := 0
	duplicates := 0

	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var event Event
		if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		receiverMu.Lock()
		if _, exists := received[event.ID]; exists {
			duplicates++
		} else {
			received[event.ID] = struct{}{}
			applied++
		}
		receiverMu.Unlock()

		if requests.Add(1) == 1 {
			close(firstReceived)
			<-releaseFirst
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()
	defer release()

	sink, err := NewWebhookSink(WebhookConfig{Endpoint: receiver.URL})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(ServiceConfig{}, txSaverDB{}, &mockRecordStore{}, outbox, nil)
	svc.AddSink(sink)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		svc.dispatchOnce(ctx, "original-claimer")
	}()

	select {
	case <-firstReceived:
	case <-ctx.Done():
		t.Fatalf("original delivery did not reach receiver: %v", ctx.Err())
	}

	// The first request is still live here. The second claim represents its
	// expired lease being stolen by another instance.
	svc.dispatchOnce(ctx, "stealing-claimer")

	receiverMu.Lock()
	gotApplied := applied
	gotDuplicates := duplicates
	receiverMu.Unlock()
	if got := requests.Load(); got != 2 {
		t.Fatalf("HTTP deliveries = %d, want 2", got)
	}
	if gotApplied != 1 || gotDuplicates != 1 {
		t.Fatalf("receiver applied=%d duplicates=%d, want 1 and 1", gotApplied, gotDuplicates)
	}
	if got := svc.DeliveryStats(context.Background()).DeliveryDuplicated; got != 1 {
		t.Fatalf("delivery_duplicated = %d, want 1", got)
	}

	release()
	select {
	case <-firstDone:
	case <-ctx.Done():
		t.Fatalf("original claimer did not finish after receiver release: %v", ctx.Err())
	}
}
