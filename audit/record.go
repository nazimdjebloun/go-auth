package audit

import (
	"context"
	"errors"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// ErrRecordBlocked is returned by Record when the enqueue failure mode is
// fail-closed and the durable write could not be committed. The operation
// that triggered the event must fail — that is what fail-closed means.
var ErrRecordBlocked = errors.New("audit: durable record write failed (fail-closed)")

// Record writes the event durably: the audit_log record joins the caller's
// transaction (record-iff-commit), and — only when external delivery sinks
// are configured — a companion audit_outbox obligation joins the same
// transaction, so delivery is attempted exactly when the state change
// committed. Two independent savepoints keep the failures distinguishable:
// a lost obligation does not imply a lost record, because the record is
// already part of the outer transaction.
//
// Events with no surrounding transaction (for example login.failed, which
// has no state change to be atomic with) take the same path — the savepoint
// is inert and the insert autocommits, which is equally durable. Atomicity
// matters only when a state change exists to be atomic with.
//
// The failure mode is resolved per event via the configured
// EnqueueFailureModeResolver (nil = fail-open everywhere):
//
//   - fail-open: a failed record insert counts record_lost and the
//     operation proceeds; a failed outbox insert counts delivery_missed.
//   - fail-closed: Record returns ErrRecordBlocked, which — inside a
//     transaction — aborts the operation. At a non-transactional site there
//     is nothing to roll back and no operation to block — the request
//     outcome is already determined — so fail-closed degrades to fail-open
//     plus record_lost. record_blocked therefore only ever fires where a
//     transaction exists.
func (s *AuditService) Record(ctx context.Context, event Event) error {
	if !s.enabled {
		return nil
	}
	if event.ID == "" {
		event.ID = generateID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if event.UserAgent != "" && event.ParsedUA == nil {
		event.ParsedUA = domain.ParseUserAgent(event.UserAgent)
	}

	mode := AuditFailureOpen
	if s.enqueueMode != nil {
		mode = s.enqueueMode(event)
	}
	// Fail-closed is only meaningful where a transaction exists to roll
	// back. Outside one, the operation cannot be aborted — degrade to
	// fail-open rather than report a failure nobody can act on.
	if mode == AuditFailureClosed && !s.db.InTx(ctx) {
		mode = AuditFailureOpen
	}

	// Storage is optional: a service built without a record store (tests,
	// or the deprecated sink-only wiring) has nothing durable to do.
	if s.recordStore == nil {
		s.runInlineSinks(ctx, event)
		return nil
	}

	// The record. Its own savepoint: a failed insert must not poison the
	// surrounding transaction before the caller even gets to choose how to
	// react. The savepoint is inert without a surrounding transaction.
	recordErr := s.db.Savepoint(ctx, "audit_record", func(spCtx context.Context) error {
		return s.recordStore.Insert(spCtx, event)
	})
	if recordErr != nil {
		if mode == AuditFailureClosed {
			s.counters.recordBlocked.Add(1)
			s.log.ErrorContext(ctx, "audit record insert failed (fail-closed)",
				"marker", "audit_record_blocked",
				"event_type", string(event.Type), "error", recordErr)
			return ErrRecordBlocked
		}
		s.counters.recordLost.Add(1)
		s.log.ErrorContext(ctx, "audit record insert failed under fail-open — record lost",
			"marker", "audit_record_lost",
			"event_type", string(event.Type), "error", recordErr)
		return nil
	}

	// Process-local sinks (the built-in logger) run inline: they cannot
	// fail in a way worth an outbox row, and they are not delivery
	// obligations.
	s.runInlineSinks(ctx, event)

	// The delivery obligation — only when an external sink exists. No
	// configured sink, no row: audit enabled with DB-only sinks costs
	// exactly one insert and no delivery machinery.
	if !s.hasDeliverySinks() {
		return nil
	}

	var outboxErr error
	if s.outbox == nil {
		outboxErr = errors.New("audit: outbox store is not configured")
	} else {
		outboxErr = s.db.Savepoint(ctx, "audit_deliver", func(spCtx context.Context) error {
			return s.outbox.Insert(spCtx, event.ID, event.OrgID, PriorityFor(event.Type), event.CreatedAt)
		})
	}
	if outboxErr != nil {
		if mode == AuditFailureClosed {
			// The record is already inserted; rolling the transaction back
			// discards it too, so the record loss and the operation failure
			// are the same event.
			s.counters.recordBlocked.Add(1)
			s.log.ErrorContext(ctx, "audit outbox insert failed (fail-closed) — rolling back operation",
				"marker", "audit_record_blocked",
				"event_type", string(event.Type), "error", outboxErr)
			return ErrRecordBlocked
		}
		// Record EXISTS, only the obligation is lost. Counted, logged,
		// permanent delivery loss with the record intact — the correct
		// severity ordering.
		s.counters.deliveryMissed.Add(1)
		s.log.ErrorContext(ctx, "audit outbox insert failed under fail-open — delivery obligation lost, record intact",
			"marker", "audit_delivery_missed",
			"event_id", event.ID, "event_type", string(event.Type), "error", outboxErr)
	}
	return nil
}

// runInlineSinks invokes process-local sinks (the built-in logger). Their
// failures are logged, never fatal: they have no delivery obligation.
func (s *AuditService) runInlineSinks(ctx context.Context, event Event) {
	for _, sink := range s.inlineSinks {
		if err := sink.Handle(ctx, event); err != nil {
			s.log.ErrorContext(ctx, "audit inline sink error",
				"sink", sinkName(sink), "error", err)
		}
	}
}
