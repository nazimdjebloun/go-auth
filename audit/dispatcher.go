package audit

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"sync/atomic"
	"time"
)

// Dispatch loop knobs. The backoff ceiling — not MaxAttempts — is the dial
// for absorbing longer outages: with MaxAttempts 10 the retry window is
// ~3h10m at a 10s base and ~9h capped, barely moving with the base.
const (
	retryBaseBackoff = 10 * time.Second
	retryMaxBackoff  = 1 * time.Hour
	// janitorInterval runs the outbox clocks and the emergency valve. The
	// orphan scan is rarer: orphans signal a broken invariant, not churn.
	janitorInterval    = time.Minute
	orphanScanInterval = time.Hour
	orphanScanLimit    = 1000

	// defaultClaimLease / minClaimLease bound the claim lease. The lease must
	// exceed the worst-case delivery time of one batch, so a floor keeps a
	// misconfigured short lease from turning every slow sink into a steal
	// race (a benign duplicate, but a needless one).
	defaultClaimLease = 10 * time.Minute
	minClaimLease     = time.Minute
)

// nextBackoff computes the retry delay for attempt n (0-based), exponential
// from retryBaseBackoff and capped at retryMaxBackoff.
func nextBackoff(attempts int) time.Duration {
	d := retryBaseBackoff
	for i := 0; i < attempts && d < retryMaxBackoff; i++ {
		d *= 2
	}
	if d > retryMaxBackoff {
		d = retryMaxBackoff
	}
	return d
}

// startDispatcher runs the outbox drain: one goroutine per worker claiming
// and delivering, plus the janitor. It starts only when at least one
// external delivery sink is configured — with a DB-only audit configuration
// there is no queue, no workers, and no dispatcher; the in-tx insert is the
// entire mechanism.
func (s *AuditService) startDispatcher(ctx context.Context) {
	if s.outbox == nil || !s.hasDeliverySinks() {
		return
	}

	for i := 0; i < s.workers; i++ {
		s.wg.Add(1)
		go s.dispatchLoop(ctx, i)
	}
	s.wg.Add(1)
	go s.janitorLoop(ctx)
}

func (s *AuditService) dispatchLoop(ctx context.Context, worker int) {
	defer s.wg.Done()
	owner := dispatchOwner(worker)
	ticker := time.NewTicker(s.dispatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.dispatchOnce(ctx, owner)
		}
	}
}

func dispatchOwner(worker int) string {
	host := "unknown"
	if h, err := os.Hostname(); err == nil {
		host = h
	}
	return host + ":worker-" + strconv.Itoa(worker)
}

// dispatchOnce claims and delivers one batch. Delivery goes through the
// existing EventSink.HandleBatch, so batching behavior and per-sink
// semantics are unchanged; FailureMode governs fan-out across sinks within
// a batch (stop-at-first-failure vs log-and-continue) and still never
// changes whether the user's request succeeded.
func (s *AuditService) dispatchOnce(ctx context.Context, owner string) {
	rows, err := s.outbox.ClaimBatch(ctx, owner, s.batchSize, s.claimLease)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			s.log.ErrorContext(ctx, "audit dispatcher claim failed", "error", err)
		}
		return
	}
	if len(rows) == 0 {
		return
	}

	events := make([]Event, len(rows))
	seenDuplicate := false
	for i, r := range rows {
		events[i] = r.Event
		if r.Stolen {
			seenDuplicate = true
		}
	}
	if seenDuplicate {
		s.counters.deliveryDuplicated.Add(1)
		s.log.WarnContext(ctx, "audit delivery duplicated — lease stolen from a stalled claimer",
			"marker", "audit_delivery_duplicated", "batch_size", len(rows))
	}

	s.mu.RLock()
	sinks := make([]EventSink, len(s.sinks))
	copy(sinks, s.sinks)
	s.mu.RUnlock()

	var sinkErr error
	for _, sink := range sinks {
		if err := sink.HandleBatch(ctx, events); err != nil {
			sinkErr = err
			if s.failureMode == AuditFailureClosed {
				s.log.ErrorContext(ctx, "audit sink batch error (fail-closed)",
					"sink", sinkName(sink), "error", err, "batch_size", len(events))
				break
			}
			s.log.ErrorContext(ctx, "audit sink batch error (fail-open)",
				"sink", sinkName(sink), "error", err, "batch_size", len(events))
		}
	}

	s.settleBatch(ctx, rows, sinkErr)
}

// settleBatch resolves each claimed row after delivery: success deletes the
// obligation (the row's existence was the pending state); failure backs off
// or dead-letters. Dead letters are marked, not deleted — the retained row
// carries the failure evidence across restarts, until DeadLetterTTL purges
// it.
func (s *AuditService) settleBatch(ctx context.Context, rows []OutboxRow, sinkErr error) {
	for _, row := range rows {
		if sinkErr == nil {
			if err := s.outbox.MarkSuccess(ctx, row.EventID); err != nil {
				s.log.ErrorContext(ctx, "audit outbox delete failed", "event_id", row.EventID, "error", err)
			}
			continue
		}
		if row.Attempts >= s.maxAttempts {
			if err := s.outbox.MarkDeadLetter(ctx, row.EventID, time.Now().UTC(), sinkErr.Error()); err != nil {
				s.log.ErrorContext(ctx, "audit outbox dead-letter failed", "event_id", row.EventID, "error", err)
				continue
			}
			s.counters.deadLettered.Add(1)
			s.log.ErrorContext(ctx, "audit delivery dead-lettered after max attempts",
				"marker", "audit_dead_lettered",
				"event_id", row.EventID, "event_type", string(row.Event.Type),
				"attempts", row.Attempts, "last_error", sinkErr.Error())
			continue
		}
		next := time.Now().UTC().Add(nextBackoff(row.Attempts))
		if err := s.outbox.MarkFailure(ctx, row.EventID, next, sinkErr.Error()); err != nil {
			s.log.ErrorContext(ctx, "audit outbox retry update failed", "event_id", row.EventID, "error", err)
		}
	}
}

// janitorLoop enforces the outbox clocks, the emergency valve, and the
// orphan scan.
func (s *AuditService) janitorLoop(ctx context.Context) {
	defer s.wg.Done()
	janitor := time.NewTicker(janitorInterval)
	defer janitor.Stop()
	orphan := time.NewTicker(orphanScanInterval)
	defer orphan.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-janitor.C:
			s.janitorOnce(ctx)
		case <-orphan.C:
			n, err := s.outbox.PurgeOrphans(ctx, orphanScanLimit)
			if err != nil {
				s.log.ErrorContext(ctx, "audit orphan scan failed", "error", err)
				continue
			}
			if n > 0 {
				s.counters.deliveryOrphaned.Add(int64(n))
				s.log.ErrorContext(ctx, "audit outbox orphans purged — obligations without records indicate a broken invariant (bypassed retention validation or manual deletes)",
					"marker", "audit_delivery_orphaned", "count", n)
			}
		}
	}
}

func (s *AuditService) janitorOnce(ctx context.Context) {
	now := time.Now().UTC()

	// The two clocks: pending rows past OutboxMaxAge are evicted (delivery
	// abandoned, record intact); dead-lettered rows past DeadLetterTTL are
	// purged (their evidence window elapsed).
	pendingEvicted, deadPurged, err := s.outbox.SweepExpired(ctx, now, s.outboxMaxAge, s.deadLetterTTL)
	if err != nil {
		s.log.ErrorContext(ctx, "audit outbox sweep failed", "error", err)
	}
	if deadPurged > 0 {
		s.counters.deliveryDropped.Add(int64(deadPurged))
	}
	if pendingEvicted > 0 {
		s.counters.deliveryDropped.Add(int64(pendingEvicted))
		s.counters.pendingDropped.Add(int64(pendingEvicted))
		// Pending eviction is loud, not just counted: obligations are being
		// abandoned under sustained pressure. An operator must not have to
		// poll stats to discover the emergency valve opened.
		s.log.ErrorContext(ctx, "audit outbox pending rows evicted past OutboxMaxAge — delivery obligations abandoned, records intact",
			"marker", "audit_delivery_dropped", "count", pendingEvicted)
	}

	// The emergency valve.
	if s.outboxMaxRows > 0 {
		evicted, pendingEvicted, err := s.outbox.EvictOverCap(ctx, s.outboxMaxRows)
		if err != nil {
			s.log.ErrorContext(ctx, "audit outbox eviction failed", "error", err)
		}
		if evicted > 0 {
			s.counters.deliveryDropped.Add(int64(evicted))
		}
		if pendingEvicted > 0 {
			s.counters.pendingDropped.Add(int64(pendingEvicted))
			s.log.ErrorContext(ctx, "audit outbox over OutboxMaxRows — pending rows evicted, delivery obligations abandoned, records intact",
				"marker", "audit_delivery_dropped", "count", pendingEvicted)
		}
	}
}

// DeliveryStats returns the observability surface. Counters are cumulative
// for the process run; the gauges come from the store. With no outbox
// configured, only the counters are meaningful (all zero).
func (s *AuditService) DeliveryStats(ctx context.Context) DeliveryStats {
	st := DeliveryStats{
		DeadLettered:       s.counters.deadLettered.Load(),
		DeliveryDropped:    s.counters.deliveryDropped.Load(),
		PendingDropped:     s.counters.pendingDropped.Load(),
		DeliveryOrphaned:   s.counters.deliveryOrphaned.Load(),
		DeliveryDuplicated: s.counters.deliveryDuplicated.Load(),
		DeliveryMissed:     s.counters.deliveryMissed.Load(),
		RecordLost:         s.counters.recordLost.Load(),
		RecordBlocked:      s.counters.recordBlocked.Load(),
	}
	if s.outbox != nil {
		if n, err := s.outbox.CountPending(ctx); err == nil {
			st.Pending = n
		}
		if age, ok, err := s.outbox.OldestPendingAge(ctx, time.Now().UTC()); err == nil && ok {
			st.OldestPendingAge = age
			st.HasPending = true
		}
	}
	return st
}

// auditCounters are cumulative, separate from the gauges, so evicting a
// dead letter does not erase the trend within a process run.
type auditCounters struct {
	deadLettered       atomic.Int64
	deliveryDropped    atomic.Int64
	pendingDropped     atomic.Int64
	deliveryOrphaned   atomic.Int64
	deliveryDuplicated atomic.Int64
	deliveryMissed     atomic.Int64
	recordLost         atomic.Int64
	recordBlocked      atomic.Int64
}

func sinkName(sink EventSink) string {
	if t := reflect.TypeOf(sink); t != nil {
		return t.String()
	}
	return "nil"
}
