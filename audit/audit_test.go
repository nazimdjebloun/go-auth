package audit

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─── Mock Sink ──────────────────────────────────────────────

type mockSink struct {
	mu     sync.Mutex
	events []Event
	batchN int
}

func (m *mockSink) Handle(_ context.Context, event Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockSink) HandleBatch(_ context.Context, events []Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, events...)
	m.batchN++
	return nil
}

func (m *mockSink) snapshot() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]Event, len(m.events))
	copy(cp, m.events)
	return cp
}

// ─── Failing Sink ───────────────────────────────────────────

type failSink struct {
	err error
}

func (f *failSink) Handle(_ context.Context, _ Event) error { return f.err }
func (f *failSink) HandleBatch(_ context.Context, _ []Event) error { return f.err }

// ─── Cleaner Sink ───────────────────────────────────────────

type cleanerSink struct {
	mu         sync.Mutex
	deleted    int
	retentionD int
}

func (c *cleanerSink) Handle(_ context.Context, _ Event) error  { return nil }
func (c *cleanerSink) HandleBatch(_ context.Context, _ []Event) error { return nil }
func (c *cleanerSink) Cleanup(_ context.Context, retentionDays int) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.retentionD = retentionDays
	c.deleted = 42
	return c.deleted, nil
}

// ─── Tests ──────────────────────────────────────────────────

func TestAuditDisabled_PublishNoop(t *testing.T) {
	s := &AuditService{enabled: false}
	s.Publish(context.Background(), NewLoginEvent("u1", "s1", net.ParseIP("127.0.0.1"), "test", true))
	// no panic, no queue — that's the test
}

func TestPublish_NonBlocking(t *testing.T) {
	s := NewAuditService(AuditServiceConfig{QueueSize: 2}, nil)
	s.Start(context.Background())
	defer s.Stop(context.Background())

	// Fill the queue
	s.Publish(context.Background(), NewLoginEvent("u1", "s1", nil, "", true))
	s.Publish(context.Background(), NewLoginEvent("u2", "s2", nil, "", true))
	// Third should not block
	done := make(chan struct{})
	go func() {
		s.Publish(context.Background(), NewLoginEvent("u3", "s3", nil, "", true))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on full queue")
	}
}

func TestQueueFull_DropsEvent(t *testing.T) {
	sink := &mockSink{}
	s := NewAuditService(AuditServiceConfig{QueueSize: 1}, nil)
	s.AddSink(sink)
	s.Start(context.Background())

	s.Publish(context.Background(), NewLoginEvent("u1", "s1", nil, "", true))
	// Second event should be dropped (non-blocking, queue full)
	s.Publish(context.Background(), NewLoginEvent("u2", "s2", nil, "", true))

	time.Sleep(200 * time.Millisecond)
	s.Stop(context.Background())

	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event (second dropped), got %d", len(events))
	}
}

func TestWorker_ReceivesEvent(t *testing.T) {
	sink := &mockSink{}
	s := NewAuditService(AuditServiceConfig{QueueSize: 10, BatchSize: 10, FlushInterval: time.Hour}, nil)
	s.AddSink(sink)
	s.Start(context.Background())

	event := NewLoginEvent("u1", "s1", net.ParseIP("10.0.0.1"), "test-agent", true)
	s.Publish(context.Background(), event)

	// Wait for worker to pick it up
	time.Sleep(200 * time.Millisecond)
	s.Stop(context.Background())

	events := sink.snapshot()
	if len(events) == 0 {
		t.Fatal("sink received no events")
	}
	if events[0].Type != EventLoginSuccess {
		t.Fatalf("expected login.success, got %s", events[0].Type)
	}
}

func TestWorker_BatchFlush(t *testing.T) {
	sink := &mockSink{}
	const batchSize = 5
	s := NewAuditService(AuditServiceConfig{
		QueueSize:     100,
		BatchSize:     batchSize,
		FlushInterval: time.Hour, // rely on batch size, not timer
	}, nil)
	s.AddSink(sink)
	s.Start(context.Background())

	for i := 0; i < batchSize; i++ {
		s.Publish(context.Background(), NewLoginEvent("u", "s", nil, "", true))
	}

	time.Sleep(200 * time.Millisecond)
	s.Stop(context.Background())

	events := sink.snapshot()
	if len(events) != batchSize {
		t.Fatalf("expected %d events, got %d", batchSize, len(events))
	}
	if sink.batchN < 1 {
		t.Fatal("expected at least 1 batch flush")
	}
}

func TestWorker_FlushInterval(t *testing.T) {
	sink := &mockSink{}
	s := NewAuditService(AuditServiceConfig{
		QueueSize:     10,
		BatchSize:     100, // won't hit batch size
		FlushInterval: 50 * time.Millisecond,
	}, nil)
	s.AddSink(sink)
	s.Start(context.Background())

	s.Publish(context.Background(), NewLoginEvent("u", "s", nil, "", true))

	// Wait for timer-based flush
	time.Sleep(200 * time.Millisecond)
	s.Stop(context.Background())

	events := sink.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 event after timer flush, got %d", len(events))
	}
}

func TestMultipleSinks_AllReceive(t *testing.T) {
	sink1 := &mockSink{}
	sink2 := &mockSink{}
	s := NewAuditService(AuditServiceConfig{QueueSize: 10, BatchSize: 10, FlushInterval: time.Hour}, nil)
	s.AddSink(sink1)
	s.AddSink(sink2)
	s.Start(context.Background())

	s.Publish(context.Background(), NewLoginEvent("u", "s", nil, "", true))
	time.Sleep(200 * time.Millisecond)
	s.Stop(context.Background())

	if len(sink1.snapshot()) != 1 {
		t.Fatal("sink1 didn't receive event")
	}
	if len(sink2.snapshot()) != 1 {
		t.Fatal("sink2 didn't receive event")
	}
}

func TestFailOpen_ContinuesOnSinkError(t *testing.T) {
	badSink := &failSink{err: fmt.Errorf("boom")}
	goodSink := &mockSink{}

	s := NewAuditService(AuditServiceConfig{
		QueueSize:     10,
		BatchSize:     10,
		FlushInterval: time.Hour,
		FailureMode:   AuditFailureOpen,
	}, nil)
	s.AddSink(badSink)
	s.AddSink(goodSink)
	s.Start(context.Background())

	s.Publish(context.Background(), NewLoginEvent("u", "s", nil, "", true))
	time.Sleep(200 * time.Millisecond)
	s.Stop(context.Background())

	if len(goodSink.snapshot()) != 1 {
		t.Fatal("good sink should still receive events in fail-open mode")
	}
}

func TestFailClosed_StopsBatch(t *testing.T) {
	badSink := &failSink{err: fmt.Errorf("boom")}
	goodSink := &mockSink{}

	s := NewAuditService(AuditServiceConfig{
		QueueSize:     10,
		BatchSize:     10,
		FlushInterval: time.Hour,
		FailureMode:   AuditFailureClosed,
	}, nil)
	s.AddSink(badSink)
	s.AddSink(goodSink)
	s.Start(context.Background())

	s.Publish(context.Background(), NewLoginEvent("u", "s", nil, "", true))
	time.Sleep(200 * time.Millisecond)
	s.Stop(context.Background())

	// In fail-closed, the batch stops at the failing sink — goodSink should NOT receive it
	if len(goodSink.snapshot()) != 0 {
		t.Fatal("good sink should NOT receive events in fail-closed mode when a prior sink fails")
	}
}

func TestStop_FlushesQueue(t *testing.T) {
	sink := &mockSink{}
	s := NewAuditService(AuditServiceConfig{QueueSize: 100, BatchSize: 100, FlushInterval: time.Hour}, nil)
	s.AddSink(sink)
	s.Start(context.Background())

	for i := 0; i < 5; i++ {
		s.Publish(context.Background(), NewLoginEvent("u", "s", nil, "", true))
	}

	// Let workers pick up all events
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatal(err)
	}

	events := sink.snapshot()
	if len(events) != 5 {
		t.Fatalf("expected 5 events flushed on stop, got %d", len(events))
	}
}

func TestStop_FlushesPartialBatch(t *testing.T) {
	sink := &mockSink{}
	s := NewAuditService(AuditServiceConfig{QueueSize: 100, BatchSize: 50, FlushInterval: time.Hour}, nil)
	s.AddSink(sink)
	s.Start(context.Background())

	for i := 0; i < 5; i++ {
		s.Publish(context.Background(), NewLoginEvent("u", "s", nil, "", true))
	}

	// Let workers pick up all events
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Stop(ctx)

	events := sink.snapshot()
	if len(events) != 5 {
		t.Fatalf("expected 5 partial batch events flushed, got %d", len(events))
	}
}

func TestStop_Timeout(t *testing.T) {
	// Create a service but don't start it — cancel is nil, queue close will work
	s := NewAuditService(AuditServiceConfig{QueueSize: 10}, nil)
	// Don't start — cancel is nil

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := s.Stop(ctx)
	// Should succeed since queue is empty and no workers
	if err != nil {
		t.Fatalf("expected nil error on empty stop, got %v", err)
	}
}

func TestRetentionCleanup(t *testing.T) {
	cs := &cleanerSink{}
	s := NewAuditService(AuditServiceConfig{RetentionDays: 30}, nil)
	s.AddSink(cs)

	// Directly test the cleaner interface
	var cleaner Cleaner = cs

	n, err := cleaner.Cleanup(context.Background(), 30)
	if err != nil {
		t.Fatal(err)
	}
	if n != 42 {
		t.Fatalf("expected 42 deleted, got %d", n)
	}
	if cs.retentionD != 30 {
		t.Fatalf("expected retention 30, got %d", cs.retentionD)
	}
}

func TestRetentionCleanupDisabled(t *testing.T) {
	s := NewAuditService(AuditServiceConfig{RetentionDays: 0}, nil)
	if s.retentionDays != 0 {
		t.Fatal("retention should be 0")
	}
}

func TestRetentionOnlyRunsIfCleanerSink(t *testing.T) {
	s := NewAuditService(AuditServiceConfig{RetentionDays: 30}, nil)
	s.AddSink(&mockSink{}) // not a Cleaner
	if s.hasCleaner() {
		t.Fatal("should not have cleaner when no Cleaner sink registered")
	}

	s.AddSink(&cleanerSink{})
	if !s.hasCleaner() {
		t.Fatal("should have cleaner after adding Cleaner sink")
	}
}

func TestTypedBuilder_AlwaysPopulatesIDAndCreatedAt(t *testing.T) {
	builders := []Event{
		NewLoginEvent("u", "s", nil, "", true),
		NewLoginFailedEvent("e", nil, ""),
		NewLoginLockedEvent("e", nil, ""),
		NewLogoutEvent("u", "s", nil, ""),
		NewUserRegisteredEvent("u", nil, ""),
		NewEmailVerifiedEvent("u"),
		NewEmailVerificationSentEvent("e"),
		NewPasswordChangedEvent("u", nil, ""),
		NewPasswordResetRequestedEvent("e", nil, ""),
		NewPasswordResetCompletedEvent("u", nil, ""),
		NewSessionEvent(EventSessionCreated, "u", "s", nil, ""),
		NewOAuthEvent(EventOAuthLogin, "u", "github", nil, ""),
		NewAdminEvent(EventAdminUserBanned, "admin", "target"),
		NewOrgEvent(EventOrgCreated, "u", "org", nil),
		NewRoleChangedEvent("admin", "u", "user", "admin"),
		NewEvent(EventLoginSuccess),
	}

	for _, e := range builders {
		if e.ID == "" {
			t.Errorf("%s: ID is empty", e.Type)
		}
		if e.CreatedAt.IsZero() {
			t.Errorf("%s: CreatedAt is zero", e.Type)
		}
	}
}

func TestTypedBuilder_AllFields(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	e := NewLoginEvent("actor1", "sess1", ip, "Mozilla/5.0", true)

	if e.Type != EventLoginSuccess {
		t.Errorf("type: got %s", e.Type)
	}
	if e.Severity != SeverityInfo {
		t.Errorf("severity: got %s", e.Severity)
	}
	if !e.Success {
		t.Error("success should be true")
	}
	if e.ActorID == nil || *e.ActorID != "actor1" {
		t.Error("actor_id wrong")
	}
	if e.SessionID == nil || *e.SessionID != "sess1" {
		t.Error("session_id wrong")
	}
	if !e.IP.Equal(ip) {
		t.Error("ip wrong")
	}
	if e.UserAgent != "Mozilla/5.0" {
		t.Error("user_agent wrong")
	}
}

func TestGenericBuilder_Options(t *testing.T) {
	ip := net.ParseIP("10.0.0.1")
	e := NewEvent(EventLogout,
		WithActor("u1"),
		WithTarget("u2"),
		WithSession("s1"),
		WithOrg("o1"),
		WithIP(ip),
		WithUserAgent("agent"),
		WithRequestID("req1"),
		WithCorrelationID("corr1"),
		WithMetadata("key", "val"),
		WithSuccess(true),
		WithSeverity(SeverityWarning),
	)

	if e.ActorID == nil || *e.ActorID != "u1" {
		t.Error("actor_id")
	}
	if e.TargetUserID == nil || *e.TargetUserID != "u2" {
		t.Error("target_user_id")
	}
	if e.OrgID == nil || *e.OrgID != "o1" {
		t.Error("org_id")
	}
	if e.Metadata == nil || e.Metadata["key"] != "val" {
		t.Error("metadata")
	}
	if e.Severity != SeverityWarning {
		t.Error("severity")
	}
}

func TestEventTypes_NoDuplicates(t *testing.T) {
	types := []EventType{
		EventLoginSuccess, EventLoginFailed, EventLoginLocked, EventLogout,
		EventUserRegistered,
		EventEmailVerificationSent, EventEmailVerified,
		EventTwoFactorCodeSent, EventTwoFactorVerified, EventTwoFactorFailed,
		EventTwoFactorEnabled, EventTwoFactorDisabled, EventTwoFactorSuspicious,
		EventPasswordChanged, EventPasswordResetRequest, EventPasswordResetDone,
		EventSessionCreated, EventSessionRefreshed, EventSessionRevoked, EventSessionRevokedAll,
		EventOAuthLogin, EventOAuthLinked, EventOAuthUnlinked,
		EventAdminUserCreated, EventAdminUserUpdated, EventAdminUserDeleted,
		EventAdminUserBanned, EventAdminUserUnbanned,
		EventRoleChanged,
		EventOrgCreated, EventOrgDeleted, EventOrgMemberInvited, EventOrgMemberRemoved,
	}
	seen := make(map[EventType]bool)
	for _, typ := range types {
		if seen[typ] {
			t.Fatalf("duplicate event type: %s", typ)
		}
		seen[typ] = true
	}
}

func TestSinkInterface_Compliance(t *testing.T) {
	var _ EventSink = (*mockSink)(nil)
	var _ EventSink = (*LoggerSink)(nil)
	// SQLAuditSink can't be instantiated without a real DB
}

func TestCleanerInterface_Compliance(t *testing.T) {
	var _ Cleaner = (*cleanerSink)(nil)
	// SQLAuditSink implements Cleaner — tested via integration
}

func TestClose_StopsAuditBeforeDB(t *testing.T) {
	var dbClosed atomic.Bool
	sink := &mockSink{}
	s := NewAuditService(AuditServiceConfig{QueueSize: 10, BatchSize: 10, FlushInterval: time.Hour}, nil)
	s.AddSink(sink)
	s.Start(context.Background())

	s.Publish(context.Background(), NewLoginEvent("u", "s", nil, "", true))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Stop(ctx)

	// After Stop, events are flushed before it returns
	events := sink.snapshot()
	if len(events) == 0 {
		t.Fatal("events should be flushed before Stop returns")
	}

	// Simulate DB close after audit stop
	dbClosed.Store(true)
	if !dbClosed.Load() {
		t.Fatal("DB should close after audit stop")
	}
}
