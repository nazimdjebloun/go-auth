package audit

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ─── Mock stores ────────────────────────────────────────────

type mockRecordStore struct {
	mu      sync.Mutex
	events  []Event
	failFor map[EventType]error
}

func (m *mockRecordStore) Insert(_ context.Context, e Event) error {
	if m.failFor != nil {
		if err, ok := m.failFor[e.Type]; ok {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *mockRecordStore) Cleanup(_ context.Context, _ int) (int, error) { return 0, nil }

func (m *mockRecordStore) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

type mockOutbox struct {
	mu      sync.Mutex
	rows    []OutboxRow
	inserts int
	fail    bool
}

func (m *mockOutbox) Insert(_ context.Context, eventID string, _ *string, _ int, _ time.Time) error {
	if m.fail {
		return errors.New("outbox down")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inserts++
	m.rows = append(m.rows, OutboxRow{EventID: eventID})
	return nil
}

func (m *mockOutbox) ClaimBatch(_ context.Context, _ string, _ int, _ time.Duration) ([]OutboxRow, error) {
	return nil, nil
}
func (m *mockOutbox) MarkSuccess(_ context.Context, _ string) error { return nil }
func (m *mockOutbox) MarkFailure(_ context.Context, _ string, _ time.Time, _ string) error {
	return nil
}
func (m *mockOutbox) MarkDeadLetter(_ context.Context, _ string, _ time.Time, _ string) error {
	return nil
}
func (m *mockOutbox) ReleaseClaim(_ context.Context, _ string) error { return nil }
func (m *mockOutbox) SweepExpired(_ context.Context, _ time.Time, _, _ time.Duration) (int, int, error) {
	return 0, 0, nil
}
func (m *mockOutbox) EvictOverCap(_ context.Context, _ int) (int, int, error) { return 0, 0, nil }
func (m *mockOutbox) PurgeOrphans(_ context.Context, _ int) (int, error)      { return 0, nil }
func (m *mockOutbox) CountPending(_ context.Context) (int, error)             { return 0, nil }
func (m *mockOutbox) OldestPendingAge(_ context.Context, _ time.Time) (time.Duration, bool, error) {
	return 0, false, nil
}

func (m *mockOutbox) insertCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.inserts
}

type noopSink struct{}

func (noopSink) Handle(context.Context, Event) error        { return nil }
func (noopSink) HandleBatch(context.Context, []Event) error { return nil }
func (noopSink) MaxBatchDeliveryTime(batchSize int) (time.Duration, bool) {
	return time.Duration(batchSize) * time.Millisecond, true
}

// failSink always fails delivery, for the retry/dead-letter paths.
type failSink struct{ err error }

func (f *failSink) Handle(context.Context, Event) error        { return f.err }
func (f *failSink) HandleBatch(context.Context, []Event) error { return f.err }
func (f *failSink) MaxBatchDeliveryTime(batchSize int) (time.Duration, bool) {
	return time.Duration(batchSize) * time.Millisecond, true
}

// txSaverDB reports an active transaction, so fail-closed stays armed. The
// production implementation is sqlstore.DB; this stands in for it in tests
// that exercise the transactional branch without a database.
type txSaverDB struct{}

func (txSaverDB) InTx(context.Context) bool { return true }
func (txSaverDB) Savepoint(ctx context.Context, _ string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
func (txSaverDB) TableExists(context.Context, string) (bool, error) { return true, nil }

type tableSaverDB struct {
	tx       bool
	exists   bool
	tableErr error
}

func (d tableSaverDB) InTx(context.Context) bool { return d.tx }
func (d tableSaverDB) Savepoint(ctx context.Context, _ string, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
func (d tableSaverDB) TableExists(context.Context, string) (bool, error) {
	return d.exists, d.tableErr
}

// ─── Tests ──────────────────────────────────────────────────

func loginEvent() Event {
	return NewLoginEvent("u1", "s1", net.ParseIP("127.0.0.1"), "test", true)
}

func TestRecord_WritesRecord_NoSinkNoOutbox(t *testing.T) {
	rec := &mockRecordStore{}
	out := &mockOutbox{}
	s := NewService(ServiceConfig{}, nil, rec, out, nil)

	if err := s.Record(context.Background(), loginEvent()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if rec.count() != 1 {
		t.Fatalf("record count = %d, want 1", rec.count())
	}
	if out.insertCount() != 0 {
		t.Fatalf("outbox rows = %d, want 0 (no external sink configured — no row nobody will consume)", out.insertCount())
	}
}

func TestRecord_SinkConfigured_WritesOutbox(t *testing.T) {
	rec := &mockRecordStore{}
	out := &mockOutbox{}
	s := NewService(ServiceConfig{}, nil, rec, out, nil)
	s.AddSink(noopSink{})

	if err := s.Record(context.Background(), loginEvent()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if out.insertCount() != 1 {
		t.Fatalf("outbox rows = %d, want 1", out.insertCount())
	}
}

func TestRecord_FailOpen_RecordLost_Counted(t *testing.T) {
	rec := &mockRecordStore{failFor: map[EventType]error{EventLoginFailed: errors.New("disk full")}}
	s := NewService(ServiceConfig{}, nil, rec, &mockOutbox{}, nil)

	// Fail-open: the operation proceeds, the loss is counted.
	if err := s.Record(context.Background(), NewLoginFailedEvent("a@b.c", net.ParseIP("127.0.0.1"), "ua")); err != nil {
		t.Fatalf("fail-open Record must not fail the operation, got %v", err)
	}
	st := s.DeliveryStats(context.Background())
	if st.RecordLost != 1 {
		t.Fatalf("record_lost = %d, want 1", st.RecordLost)
	}
}

func TestRecord_FailClosed_Blocks(t *testing.T) {
	rec := &mockRecordStore{failFor: map[EventType]error{EventLoginFailed: errors.New("disk full")}}
	s := NewService(ServiceConfig{
		EnqueueFailureMode: func(_ Event) FailureMode {
			return FailureClosed
		},
	}, txSaverDB{}, rec, &mockOutbox{}, nil)

	err := s.Record(context.Background(), NewLoginFailedEvent("a@b.c", net.ParseIP("127.0.0.1"), "ua"))
	if !errors.Is(err, ErrRecordBlocked) {
		t.Fatalf("fail-closed Record err = %v, want ErrRecordBlocked", err)
	}
	st := s.DeliveryStats(context.Background())
	if st.RecordBlocked != 1 {
		t.Fatalf("record_blocked = %d, want 1", st.RecordBlocked)
	}
}

// TestRecord_FailClosed_DegradesOutsideTx pins the rule that fail-closed is
// only meaningful where a transaction exists to roll back: at a
// non-transactional site (here: no tx in ctx) it degrades to fail-open and
// the loss is counted, rather than aborting an operation that already
// happened.
func TestRecord_FailClosed_DegradesOutsideTx(t *testing.T) {
	rec := &mockRecordStore{failFor: map[EventType]error{EventLoginFailed: errors.New("disk full")}}
	s := NewService(ServiceConfig{
		EnqueueFailureMode: func(_ Event) FailureMode { return FailureClosed },
	}, nil, rec, &mockOutbox{}, nil) // nil db → noopSaverDB → InTx false

	err := s.Record(context.Background(), NewLoginFailedEvent("a@b.c", nil, ""))
	if err != nil {
		t.Fatalf("outside a transaction fail-closed must degrade to fail-open, got %v", err)
	}
	st := s.DeliveryStats(context.Background())
	if st.RecordLost != 1 || st.RecordBlocked != 0 {
		t.Fatalf("record_lost=%d record_blocked=%d, want 1 and 0", st.RecordLost, st.RecordBlocked)
	}
}

func TestRecord_NilResolver_DefaultsFailOpen(t *testing.T) {
	rec := &mockRecordStore{failFor: map[EventType]error{EventLoginFailed: errors.New("disk full")}}
	s := NewService(ServiceConfig{}, nil, rec, &mockOutbox{}, nil)

	if err := s.Record(context.Background(), NewLoginFailedEvent("a@b.c", nil, "")); err != nil {
		t.Fatalf("nil resolver must default to fail-open, got %v", err)
	}
	if s.DeliveryStats(context.Background()).RecordLost != 1 {
		t.Fatal("record_lost not counted")
	}
}

func TestRecord_OutboxFailure_FailOpen_DeliveryMissed(t *testing.T) {
	rec := &mockRecordStore{}
	out := &mockOutbox{fail: true}
	s := NewService(ServiceConfig{}, nil, rec, out, nil)
	s.AddSink(noopSink{})

	if err := s.Record(context.Background(), loginEvent()); err != nil {
		t.Fatalf("fail-open outbox failure must not fail the operation: %v", err)
	}
	// Record EXISTS, only the obligation is lost.
	if rec.count() != 1 {
		t.Fatalf("record count = %d, want 1 (record intact)", rec.count())
	}
	st := s.DeliveryStats(context.Background())
	if st.DeliveryMissed != 1 {
		t.Fatalf("delivery_missed = %d, want 1", st.DeliveryMissed)
	}
}

func TestRecord_OutboxFailure_FailClosed_Blocks(t *testing.T) {
	rec := &mockRecordStore{}
	out := &mockOutbox{fail: true}
	s := NewService(ServiceConfig{
		EnqueueFailureMode: func(_ Event) FailureMode { return FailureClosed },
	}, txSaverDB{}, rec, out, nil)
	s.AddSink(noopSink{})

	if err := s.Record(context.Background(), loginEvent()); !errors.Is(err, ErrRecordBlocked) {
		t.Fatalf("fail-closed outbox failure err = %v, want ErrRecordBlocked", err)
	}
}

func TestRecord_SinkConfiguredWithoutOutboxDoesNotPanic(t *testing.T) {
	rec := &mockRecordStore{}
	s := NewService(ServiceConfig{}, nil, rec, nil, nil)
	s.AddSink(noopSink{})

	if err := s.Record(context.Background(), loginEvent()); err != nil {
		t.Fatalf("fail-open missing outbox must not panic or fail the operation: %v", err)
	}
	st := s.DeliveryStats(context.Background())
	if st.DeliveryMissed != 1 {
		t.Fatalf("delivery_missed = %d, want 1", st.DeliveryMissed)
	}
}

func TestRecord_NoStorage_InlineOnly_NoPanic(t *testing.T) {
	s := NewService(ServiceConfig{}, nil, nil, nil, nil)
	if err := s.Record(context.Background(), loginEvent()); err != nil {
		t.Fatalf("Record without storage: %v", err)
	}
}

func TestPriorityFor_BestEffortIsAdversarial(t *testing.T) {
	// login.failed is the event an attacker can flood: it must ship
	// best-effort so it cannot starve the discrete compromise signals.
	if got := PriorityFor(EventLoginFailed); got != PriorityBestEffort {
		t.Errorf("login.failed priority = %d, want best-effort (%d)", got, PriorityBestEffort)
	}
	if got := PriorityFor(EventAdminLoginFailed); got != PriorityBestEffort {
		t.Errorf("admin.login.failed priority = %d, want best-effort", got)
	}
	// The low-volume, high-severity signals of successful compromise ship
	// critical — they are what a login.failed flood would otherwise starve.
	for _, typ := range []EventType{EventRoleChanged, EventSessionRevoked, EventAccountDeleted, EventLoginSuccess} {
		if got := PriorityFor(typ); got != PriorityCritical {
			t.Errorf("%s priority = %d, want critical", typ, got)
		}
	}
}

func TestNextBackoff_Capped(t *testing.T) {
	if got := nextBackoff(0); got != retryBaseBackoff {
		t.Errorf("first backoff = %v, want %v", got, retryBaseBackoff)
	}
	if got := nextBackoff(2); got != 40*time.Second {
		t.Errorf("third backoff = %v, want 40s", got)
	}
	// The cap, not MaxAttempts, is what bounds the retry window.
	if got := nextBackoff(20); got != retryMaxBackoff {
		t.Errorf("capped backoff = %v, want %v", got, retryMaxBackoff)
	}
}

func TestDefaultConfig_OutboxClocks(t *testing.T) {
	cfg := defaultConfig(ServiceConfig{})
	if cfg.MaxAttempts != 10 || cfg.ClaimLease != 10*time.Minute {
		t.Errorf("defaults: maxAttempts=%d lease=%v", cfg.MaxAttempts, cfg.ClaimLease)
	}
	if cfg.OutboxMaxAge != 7*24*time.Hour || cfg.DeadLetterTTL != 7*24*time.Hour {
		t.Errorf("clock defaults: age=%v ttl=%v", cfg.OutboxMaxAge, cfg.DeadLetterTTL)
	}
	if cfg.OutboxMaxRows != 100000 {
		t.Errorf("cap default = %d", cfg.OutboxMaxRows)
	}
}

func TestValidateConfig_ClaimLeaseFloor(t *testing.T) {
	// A lease shorter than the floor turns routine delivery into a steal
	// race; startup must reject it rather than let it run.
	err := ValidateConfig(ServiceConfig{ClaimLease: time.Second})
	if err == nil {
		t.Fatal("a 1s ClaimLease must be rejected")
	}
	if err := ValidateConfig(ServiceConfig{ClaimLease: time.Minute}); err != nil {
		t.Fatalf("a 1m ClaimLease should pass the floor: %v", err)
	}
	// Unset is defaulted, not rejected.
	if err := ValidateConfig(ServiceConfig{}); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
}

func TestValidateConfig_RetentionMustExceedOutboxLifetime(t *testing.T) {
	// Retention shorter than the worst-case row lifetime would delete a
	// record whose obligation still exists — the exact defect the clock
	// analysis names.
	err := ValidateConfig(ServiceConfig{RetentionDays: 1})
	if err == nil {
		t.Fatal("RetentionDays=1 with 7d outbox clocks must be rejected")
	}
	if err := ValidateConfig(ServiceConfig{RetentionDays: 30}); err != nil {
		t.Fatalf("RetentionDays=30 should comfortably exceed 7d+7d: %v", err)
	}
	// RetentionDays 0 (keep forever) has no conflict.
	if err := ValidateConfig(ServiceConfig{RetentionDays: 0}); err != nil {
		t.Fatalf("keep-forever retention must validate: %v", err)
	}
}

func TestValidateConfig_FiniteRetentionRejectsUnboundedOutboxClocks(t *testing.T) {
	tests := []struct {
		name string
		cfg  ServiceConfig
	}{
		{
			name: "unbounded pending lifetime",
			cfg: ServiceConfig{
				RetentionDays: 30,
				OutboxMaxAge:  -1,
			},
		},
		{
			name: "unbounded dead-letter lifetime",
			cfg: ServiceConfig{
				RetentionDays: 30,
				DeadLetterTTL: -1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateConfig(tt.cfg); err == nil {
				t.Fatal("finite retention must reject an unbounded outbox clock")
			}
		})
	}

	if err := ValidateConfig(ServiceConfig{OutboxMaxAge: -1, DeadLetterTTL: -1}); err != nil {
		t.Fatalf("keep-forever audit retention may use unbounded outbox clocks: %v", err)
	}
}

func TestValidateConfig_ClaimLeaseExceedsSinkBatchTime(t *testing.T) {
	sink, err := NewWebhookSink(WebhookConfig{
		Endpoint: "https://example.test/audit",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateConfig(ServiceConfig{
		BatchSize:  50,
		ClaimLease: time.Minute,
	}, sink); err == nil {
		t.Fatal("1m claim lease must be rejected for a 100s webhook batch")
	}
	if err := ValidateConfig(ServiceConfig{
		BatchSize:  50,
		ClaimLease: 2 * time.Minute,
	}, sink); err != nil {
		t.Fatalf("2m claim lease should exceed a 100s webhook batch: %v", err)
	}
	if err := ValidateConfig(ServiceConfig{}, sink); err != nil {
		t.Fatalf("defaults must cover the default webhook batch bound: %v", err)
	}
}

func TestValidateConfig_ExternalSinkMustDeclareBound(t *testing.T) {
	type unboundedSink struct{ EventSink }
	if err := ValidateConfig(ServiceConfig{}, unboundedSink{}); err == nil {
		t.Fatal("external sink without BatchDeliveryTimeBounder must be rejected")
	}
}

func TestStart_RejectsMissingOutboxPrerequisites(t *testing.T) {
	tests := []struct {
		name   string
		db     saverDB
		outbox OutboxStore
	}{
		{name: "outbox store", db: tableSaverDB{exists: true}},
		{name: "database handle", outbox: &mockOutbox{}},
		{name: "outbox table", db: tableSaverDB{}, outbox: &mockOutbox{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewService(ServiceConfig{}, tt.db, &mockRecordStore{}, tt.outbox, nil)
			s.AddSink(noopSink{})
			if err := s.Start(context.Background()); err == nil {
				t.Fatalf("Start must reject missing %s", tt.name)
			}
		})
	}
}

func TestStart_PropagatesTableCheckError(t *testing.T) {
	want := errors.New("database unavailable")
	s := NewService(ServiceConfig{}, tableSaverDB{tableErr: want}, &mockRecordStore{}, &mockOutbox{}, nil)
	s.AddSink(noopSink{})
	if err := s.Start(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Start error = %v, want wrapped table check error", err)
	}
}

func TestRetryWindowFor_CapDominated(t *testing.T) {
	// The backoff ceiling, not MaxAttempts, sets the window: doubling
	// attempts from 10 must not grow it by more than the capped hour.
	w10 := retryWindowFor(10)
	w20 := retryWindowFor(20)
	if w10 < time.Hour || w20 > w10+11*time.Hour+time.Minute {
		t.Fatalf("retryWindowFor: w10=%v w20=%v — MaxAttempts should not dominate the 1h cap", w10, w20)
	}
	if w20 <= w10 {
		t.Fatalf("more attempts must not shrink the window: %v vs %v", w20, w10)
	}
}

func TestValidateConfig_OutboxMaxRowsMustBeExplicit(t *testing.T) {
	if err := ValidateConfig(ServiceConfig{OutboxMaxRows: -1}); err != nil {
		t.Fatalf("negative (explicitly unbounded) must be accepted: %v", err)
	}
}

func TestBestEffortSet_OnlyFloodableFailures(t *testing.T) {
	for typ := range bestEffortTypes {
		if !strings.Contains(string(typ), "failed") && !strings.Contains(string(typ), "suspicious") {
			t.Errorf("best-effort set contains %s: only attacker-floodable failure events belong there", typ)
		}
	}
}
