package audit

import (
	"context"
	"time"
)

// EnqueueFailureModeResolver decides the enqueue failure mode per event.
// It is a function rather than a config table so a deployer can key on
// whatever they consider privileged — event type, actor role, target org —
// without the library inventing a taxonomy. Nil means every event is
// fail-open (the default; see D1 in the audit durability design).
type EnqueueFailureModeResolver func(event Event) FailureMode

// OutboxRow is one claimed delivery obligation: the event rebuilt from its
// audit_log record plus the attempt count so far. Stolen marks a row whose
// claim was taken from a previous (stalled or crashed) claimer — a benign
// duplicate under at-least-once delivery.
type OutboxRow struct {
	EventID  string
	Attempts int
	Stolen   bool
	Event    Event
}

// OutboxStore is the durable-delivery queue. Implementations live in
// internal/sqlstore; the dispatcher and write path depend on this interface.
type OutboxStore interface {
	// Insert records a delivery obligation; joins the caller's transaction.
	Insert(ctx context.Context, eventID string, orgID *string, priority int, now time.Time) error
	// ClaimBatch claims up to batchSize deliverable rows for owner via a
	// guarded CAS + lease. A row claimed by a crashed (or slow) instance is
	// stealable after the lease expires — a benign duplicate under
	// at-least-once delivery.
	ClaimBatch(ctx context.Context, owner string, batchSize int, lease time.Duration) ([]OutboxRow, error)
	// MarkSuccess deletes the obligation; the row's existence was the
	// pending state.
	MarkSuccess(ctx context.Context, eventID string) error
	// MarkFailure schedules the next attempt (backoff computed by the caller)
	// and releases the claim.
	MarkFailure(ctx context.Context, eventID string, nextAttemptAt time.Time, lastErr string) error
	// MarkDeadLetter retains the row with a terminal-failure timestamp until
	// DeadLetterTTL purges it — the evidence survives restarts.
	MarkDeadLetter(ctx context.Context, eventID string, deadLetteredAt time.Time, lastErr string) error
	// ReleaseClaim gives a claimed row back without counting an attempt.
	ReleaseClaim(ctx context.Context, eventID string) error
	// SweepExpired enforces OutboxMaxAge (pending) and DeadLetterTTL (dead
	// letters), reporting each class separately.
	SweepExpired(ctx context.Context, now time.Time, outboxMaxAge, deadLetterTTL time.Duration) (pendingEvicted, deadPurged int, err error)
	// EvictOverCap sheds rows when OutboxMaxRows binds: dead letters first,
	// then oldest pending. Never touches audit_log.
	EvictOverCap(ctx context.Context, maxRows int) (evicted, pendingEvicted int, err error)
	// PurgeOrphans removes obligations whose record no longer exists. A
	// non-zero rate signals a broken invariant, not routine pressure.
	PurgeOrphans(ctx context.Context, limit int) (int, error)
	CountPending(ctx context.Context) (int, error)
	OldestPendingAge(ctx context.Context, now time.Time) (time.Duration, bool, error)
}

// RecordStore writes audit_log rows in the caller's transaction (the
// record-iff-commit write path) and owns the compliance retention deletes.
type RecordStore interface {
	Insert(ctx context.Context, event Event) error
	Cleanup(ctx context.Context, retentionDays int) (int, error)
}

// Delivery priority tiers (D5: dispatch priority only — the mapping is
// hard-coded in the library and affects order, never durability; every event
// is recorded durably, so mis-tiering can change latency but cannot lose
// data).
const (
	// PriorityCritical ships first: the low-volume, high-severity signals of
	// successful compromise must not starve behind attacker-generated noise.
	PriorityCritical = 0
	// PriorityBestEffort is for the events an attacker can generate at will.
	// Keying the highest priority on login.failed would hand the attacker
	// the starvation knob over session.revoked / role.changed /
	// account.deleted — the breach hides behind the volume.
	PriorityBestEffort = 1
)

// bestEffortTypes is the adversarial-hardening call (OD4): failed
// authentication attempts are exactly what an attacker can flood, so they
// ship behind critical events. Everything else is critical. Within a tier,
// oldest-first ordering delivers attack onset earliest.
var bestEffortTypes = map[EventType]bool{
	EventLoginFailed:         true,
	EventAdminLoginFailed:    true,
	EventTwoFactorFailed:     true,
	EventTwoFactorSuspicious: true,
}

func PriorityFor(t EventType) int {
	if bestEffortTypes[t] {
		return PriorityBestEffort
	}
	return PriorityCritical
}

// DeliveryStats is the observability surface that makes fail-open honest.
// Gauges describe current state; counters are cumulative for the process
// run and survive row eviction.
type DeliveryStats struct {
	// Pending is the number of rows awaiting delivery (gauge).
	Pending int
	// OldestPendingAge is the age of the oldest undelivered row — the
	// primary alert: delivery has been broken for N minutes/hours.
	OldestPendingAge time.Duration
	HasPending       bool
	// DeadLettered is the cumulative total past MaxAttempts for this run.
	DeadLettered int64
	// DeliveryDropped counts obligations evicted by cap/age; the record
	// stays intact.
	DeliveryDropped int64
	// PendingDropped is the subset of DeliveryDropped that was still
	// pending — obligations abandoned under sustained pressure. Any
	// non-zero value is loud (see the janitor's ERROR log).
	PendingDropped int64
	// DeliveryOrphaned counts obligations whose record no longer existed.
	// A non-zero rate means a broken invariant (bypassed retention
	// validation, manual deletes), not backlog pressure.
	DeliveryOrphaned int64
	// DeliveryDuplicated counts benign duplicate deliveries after a lease
	// steal; a rising rate reveals a lease that is too short.
	DeliveryDuplicated int64
	// DeliveryMissed counts outbox inserts that failed under fail-open;
	// the record is intact, the obligation is lost.
	DeliveryMissed int64
	// RecordLost counts audit_log inserts that failed under fail-open —
	// the exact condition this design exists to eliminate. Zero-or-alert.
	RecordLost int64
	// RecordBlocked counts fail-closed refusals of an operation — a
	// user-visible failure, distinct from suppressed loss.
	RecordBlocked int64
}
