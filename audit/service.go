package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/id"
)

type FailureMode int

const (
	FailureOpen FailureMode = iota
	FailureClosed
)

type ServiceConfig struct {
	FailureMode FailureMode
	// Deprecated: the in-memory queue is gone — the outbox is the queue.
	// Retained so existing config wiring compiles; ignored.
	QueueSize int
	// Workers is the dispatcher worker count (default 3).
	Workers int
	// BatchSize is the dispatch claim/delivery batch size (default 50).
	BatchSize int
	// FlushInterval is the dispatch poll interval (default 100ms). The name
	// is historical; nothing in-process is flushed — the database is the
	// queue, so there is no shutdown drain.
	FlushInterval time.Duration
	RetentionDays int

	// EnqueueFailureMode resolves the enqueue failure mode per event
	// (nil = fail-open for every event — availability wins for a library
	// others embed).
	EnqueueFailureMode EnqueueFailureModeResolver

	// MaxAttempts before a row is dead-lettered (default 10).
	MaxAttempts int
	// ClaimLease bounds how long a claim owns a row before it is stealable
	// (default 10m). Must exceed each sink's worst-case batch delivery time — an
	// undersized lease turns the steal race from rare into routine.
	ClaimLease time.Duration
	// OutboxMaxAge bounds a pending row from insert (default 7d; negative
	// disables the age bound).
	OutboxMaxAge time.Duration
	// DeadLetterTTL bounds a dead-lettered row's evidence window from
	// dead_lettered_at (default 7d; negative keeps them forever).
	DeadLetterTTL time.Duration
	// OutboxMaxRows is the emergency valve on outbox size (default 100000;
	// negative = unbounded). Eviction never touches audit_log.
	OutboxMaxRows int
}

// ValidateConfig enforces the relationships the outbox clocks depend on.
// It is called by the library's own construction (audit enabled) and is
// safe for a consumer to call directly. Nil error means the configuration
// is coherent.
//
// The two rules come from the design's clock analysis:
//
//   - ClaimLease must exceed the worst-case delivery time of one batch
//     (per-sink timeout × BatchSize, with a floor) — an undersized lease
//     turns the steal race from rare into routine.
//   - max(OutboxMaxAge, retryWindow + DeadLetterTTL) < RetentionDays, so
//     retention never deletes an audit_log row while its obligation still
//     exists — which would orphan a delivery that can never succeed.
func ValidateConfig(cfg ServiceConfig, sinks ...EventSink) error {
	cfg = defaultConfig(cfg)

	if cfg.ClaimLease < minClaimLease {
		return fmt.Errorf("audit: ClaimLease %v is below the %v floor — a shorter lease makes routine delivery a steal race; raise ClaimLease or leave it unset (default %v)",
			cfg.ClaimLease, minClaimLease, defaultClaimLease)
	}
	for _, sink := range sinks {
		bounder, ok := sink.(BatchDeliveryTimeBounder)
		if !ok {
			return fmt.Errorf("audit: external sink %s does not declare a finite batch delivery bound (implement audit.BatchDeliveryTimeBounder)", sinkName(sink))
		}
		maxDelivery, bounded := bounder.MaxBatchDeliveryTime(cfg.BatchSize)
		if !bounded || maxDelivery <= 0 {
			return fmt.Errorf("audit: external sink %s has no finite batch delivery bound", sinkName(sink))
		}
		if cfg.ClaimLease <= maxDelivery {
			return fmt.Errorf("audit: ClaimLease %v must be greater than sink %s worst-case batch delivery time %v (BatchSize=%d)",
				cfg.ClaimLease, sinkName(sink), maxDelivery, cfg.BatchSize)
		}
	}

	if cfg.RetentionDays > 0 {
		if cfg.OutboxMaxAge < 0 || cfg.DeadLetterTTL < 0 {
			return fmt.Errorf("audit: finite RetentionDays %d requires finite outbox clocks (OutboxMaxAge=%v, DeadLetterTTL=%v)",
				cfg.RetentionDays, cfg.OutboxMaxAge, cfg.DeadLetterTTL)
		}
		retryWindow := retryWindowFor(cfg.MaxAttempts)
		worst := cfg.OutboxMaxAge
		if alt := retryWindow + cfg.DeadLetterTTL; alt > worst {
			worst = alt
		}
		retention := time.Duration(cfg.RetentionDays) * 24 * time.Hour
		if worst >= retention {
			return fmt.Errorf("audit: RetentionDays %d (%v) is not greater than the worst-case outbox row lifetime %v (max(OutboxMaxAge=%v, retryWindow=%v + DeadLetterTTL=%v)) — retention would delete a record whose delivery obligation still exists, orphaning it",
				cfg.RetentionDays, retention, worst, cfg.OutboxMaxAge, retryWindow, cfg.DeadLetterTTL)
		}
	}

	if cfg.OutboxMaxRows == 0 {
		return errors.New("audit: OutboxMaxRows must be non-zero (negative disables the cap explicitly)")
	}

	return nil
}

// retryWindowFor is the time MaxAttempts retries under capped exponential
// backoff can take: the sum of nextBackoff(0..MaxAttempts-1).
func retryWindowFor(maxAttempts int) time.Duration {
	var total time.Duration
	for i := 0; i < maxAttempts; i++ {
		total += nextBackoff(i)
	}
	return total
}

func defaultConfig(cfg ServiceConfig) ServiceConfig {
	if cfg.Workers <= 0 {
		cfg.Workers = 3
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 100 * time.Millisecond
	}
	if cfg.RetentionDays < 0 {
		cfg.RetentionDays = 0
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 10
	}
	if cfg.ClaimLease <= 0 {
		cfg.ClaimLease = defaultClaimLease
	}
	if cfg.OutboxMaxAge == 0 {
		cfg.OutboxMaxAge = 7 * 24 * time.Hour
	}
	if cfg.DeadLetterTTL == 0 {
		cfg.DeadLetterTTL = 7 * 24 * time.Hour
	}
	if cfg.OutboxMaxRows == 0 {
		cfg.OutboxMaxRows = 100000
	}
	return cfg
}

// Service is the durable audit pipeline. Records are written in the
// caller's transaction by Record; external delivery sinks are fed from the
// audit_outbox table by the dispatcher. The in-memory queue this type once
// owned — and its drop-on-full behavior and shutdown drain — are gone: the
// database is the queue.
type Service struct {
	recordStore RecordStore
	outbox      OutboxStore
	db          saverDB // savepoints + table check; nil in sink-only tests

	// sinks are external delivery sinks. When any are configured, one outbox
	// row tracks fan-out of the event to the complete configured sink set.
	sinks []EventSink
	// inlineSinks are process-local sinks (the built-in logger), invoked at
	// record time. They are not delivery obligations.
	inlineSinks []EventSink

	failureMode FailureMode
	enqueueMode EnqueueFailureModeResolver
	enabled     bool

	workers          int
	batchSize        int
	dispatchInterval time.Duration
	retentionDays    int
	maxAttempts      int
	claimLease       time.Duration
	outboxMaxAge     time.Duration
	deadLetterTTL    time.Duration
	outboxMaxRows    int

	counters auditCounters

	log *slog.Logger
	mu  sync.RWMutex

	storageConfigured bool

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// saverDB is the slice of *sqlstore.DB the write path needs: savepoint
// wrapping and the startup table check. Declared as an interface so
// sink-only tests can run without a database.
type saverDB interface {
	// InTx reports whether ctx carries an active transaction (see
	// txFromContext): false means the caller is not inside WithTx and
	// savepoints are inert.
	InTx(ctx context.Context) bool
	Savepoint(ctx context.Context, name string, fn func(ctx context.Context) error) error
	TableExists(ctx context.Context, table string) (bool, error)
}

// noopSaverDB is the fallback when the service is built without a database
// handle (tests, or a wiring mistake): savepoints become direct calls so the
// inserts still run, and TableExists reports true so a delivery dispatcher
// never silences itself on the check.
type noopSaverDB struct{}

func (noopSaverDB) InTx(context.Context) bool { return false }
func (noopSaverDB) Savepoint(ctx context.Context, _ string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
func (noopSaverDB) TableExists(context.Context, string) (bool, error) { return true, nil }

// NewService builds the durable audit pipeline. recordStore writes the
// audit_log rows (in the caller's transaction); outbox is the durable
// delivery queue (nil when the consumer runs no external sinks, in which
// case db may also be nil). The dispatcher only starts when at least one
// external delivery sink is registered via AddSink.
func NewService(cfg ServiceConfig, db saverDB, recordStore RecordStore, outbox OutboxStore, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	cfg = defaultConfig(cfg)
	storageConfigured := db != nil
	if db == nil {
		db = noopSaverDB{}
	}
	return &Service{
		db:                db,
		recordStore:       recordStore,
		outbox:            outbox,
		failureMode:       cfg.FailureMode,
		enqueueMode:       cfg.EnqueueFailureMode,
		enabled:           true,
		workers:           cfg.Workers,
		batchSize:         cfg.BatchSize,
		dispatchInterval:  cfg.FlushInterval,
		retentionDays:     cfg.RetentionDays,
		maxAttempts:       cfg.MaxAttempts,
		claimLease:        cfg.ClaimLease,
		outboxMaxAge:      cfg.OutboxMaxAge,
		deadLetterTTL:     cfg.DeadLetterTTL,
		outboxMaxRows:     cfg.OutboxMaxRows,
		log:               log,
		storageConfigured: storageConfigured,
	}
}

// AddSink registers an external delivery sink. When at least one exists,
// each event gets one audit_outbox row; the dispatcher fans that obligation
// out to the complete sink set with at-least-once semantics. Consumers
// deduplicate on the event's id.
func (s *Service) AddSink(sink EventSink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sinks = append(s.sinks, sink)
}

// AddInlineSink registers a process-local sink (the built-in logger). It is
// invoked at record time, not via the outbox: it cannot fail in a way worth
// a delivery obligation.
func (s *Service) AddInlineSink(sink EventSink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inlineSinks = append(s.inlineSinks, sink)
}

func (s *Service) hasDeliverySinks() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sinks) > 0
}

// Start validates durable-delivery prerequisites before launching background
// workers. A configured external sink requires a real outbox store, a database
// handle, the audit_outbox table, and a finite delivery-time declaration.
func (s *Service) Start(ctx context.Context) error {
	s.mu.RLock()
	sinks := append([]EventSink(nil), s.sinks...)
	s.mu.RUnlock()

	cfg := ServiceConfig{
		Workers:       s.workers,
		BatchSize:     s.batchSize,
		FlushInterval: s.dispatchInterval,
		RetentionDays: s.retentionDays,
		MaxAttempts:   s.maxAttempts,
		ClaimLease:    s.claimLease,
		OutboxMaxAge:  s.outboxMaxAge,
		DeadLetterTTL: s.deadLetterTTL,
		OutboxMaxRows: s.outboxMaxRows,
	}
	if err := ValidateConfig(cfg, sinks...); err != nil {
		return err
	}
	if len(sinks) > 0 {
		if s.outbox == nil {
			return errors.New("audit: external sinks require an outbox store")
		}
		if !s.storageConfigured {
			return errors.New("audit: external sinks require a database handle")
		}
		ok, err := s.db.TableExists(ctx, "audit_outbox")
		if err != nil {
			return fmt.Errorf("audit: check audit_outbox table: %w", err)
		}
		if !ok {
			return errors.New("audit: audit_outbox table is missing; run the audit_outbox migration")
		}
	}

	ctx, s.cancel = context.WithCancel(ctx)
	s.startDispatcher(ctx)

	if s.recordStore != nil && s.retentionDays > 0 {
		s.wg.Add(1)
		go s.startRetentionCleanup(ctx)
	}
	return nil
}

// Stop cancels the dispatcher and janitor and waits for them. No shutdown
// drain is required: the queue is the database, so there is nothing
// in-process to lose.
func (s *Service) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) startRetentionCleanup(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := s.recordStore.Cleanup(ctx, s.retentionDays)
			if err != nil {
				s.log.ErrorContext(ctx, "audit retention cleanup failed", "error", err)
			} else if deleted > 0 {
				s.log.InfoContext(ctx, "audit retention cleanup completed", "deleted", deleted)
			}
		}
	}
}

// generateID is a package-local alias for internal/id.New. It stays a wrapper
// rather than being inlined at the call sites because "id" is already a
// parameter name in this package (see builder.go WithRequestID), and an
// id.New() call in that scope would resolve to the parameter.
func generateID() string {
	return id.New()
}
