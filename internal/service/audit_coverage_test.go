package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

// Tests for audit coverage of the previously-silent service paths: user
// login failure, session revocation (single/many), name change, and
// self-service account deletion. Each uses the recording MockAuditPublisher
// and asserts the event that must (or must not) be published.

func newAuditTestAuthService(t *testing.T, auditPub *testutil.MockAuditPublisher) (*AuthService, *testutil.MockUserRepo, *testutil.MockSessionRepo) {
	t.Helper()
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	cfg := defaultTestConfig()
	cfg.Audit = auditPub
	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg, sessSvc, nil, nil)
	return svc, users, sessions
}

func seedAuditPasswordUser(t *testing.T, users *testutil.MockUserRepo, id, email, password string) *domain.User {
	t.Helper()
	hasher := &testutil.MockHasher{}
	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	user := &domain.User{
		ID:           id,
		Email:        email,
		PasswordHash: &hash,
		Name:         "Original",
		Role:         domain.RoleUser,
		IsVerified:   true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	return user
}

func findEvent(events []audit.Event, typ audit.EventType) *audit.Event {
	for i := range events {
		if events[i].Type == typ {
			return &events[i]
		}
	}
	return nil
}

func TestLogin_Failure_PublishesLoginFailed(t *testing.T) {
	auditPub := testutil.NewMockAuditPublisher()
	svc, users, _ := newAuditTestAuthService(t, auditPub)
	seedAuditPasswordUser(t, users, "user-1", "alice@example.com", "Passw0rd!")

	if _, err := svc.Login(context.Background(), LoginInput{
		Email: "alice@example.com", Password: "wrong-password", IP: "10.0.0.9",
	}); err == nil {
		t.Fatal("expected login failure")
	}

	event := findEvent(auditPub.Events, audit.EventLoginFailed)
	if event == nil {
		t.Fatalf("expected a login.failed event, got %+v", auditPub.Events)
	}
	if event.Success {
		t.Error("expected login.failed Success=false")
	}
	if event.Severity != audit.SeverityWarning {
		t.Errorf("expected SeverityWarning, got %s", event.Severity)
	}
	if event.ActorID == nil || *event.ActorID != "alice@example.com" {
		t.Errorf("expected ActorID alice@example.com, got %+v", event.ActorID)
	}
	if event.IP == nil || event.IP.String() != "10.0.0.9" {
		t.Errorf("expected IP 10.0.0.9, got %+v", event.IP)
	}
}

func TestLogin_Failure_UnknownEmail_PublishesLoginFailed(t *testing.T) {
	auditPub := testutil.NewMockAuditPublisher()
	svc, _, _ := newAuditTestAuthService(t, auditPub)

	if _, err := svc.Login(context.Background(), LoginInput{
		Email: "nobody@example.com", Password: "Passw0rd!",
	}); err == nil {
		t.Fatal("expected login failure for unknown email")
	}
	if findEvent(auditPub.Events, audit.EventLoginFailed) == nil {
		t.Fatalf("expected a login.failed event for unknown email, got %+v", auditPub.Events)
	}
}

func TestChangeName_PublishesNameChanged(t *testing.T) {
	auditPub := testutil.NewMockAuditPublisher()
	svc, users, _ := newAuditTestAuthService(t, auditPub)
	seedAuditPasswordUser(t, users, "user-1", "alice@example.com", "Passw0rd!")

	if err := svc.ChangeName(context.Background(), "user-1", "New Name"); err != nil {
		t.Fatalf("ChangeName: %v", err)
	}

	event := findEvent(auditPub.Events, audit.EventNameChanged)
	if event == nil {
		t.Fatalf("expected a user.name_changed event, got %+v", auditPub.Events)
	}
	if event.ActorID == nil || *event.ActorID != "user-1" {
		t.Errorf("expected ActorID user-1, got %+v", event.ActorID)
	}
}

func TestDeleteAccount_PublishesAccountDeleted(t *testing.T) {
	auditPub := testutil.NewMockAuditPublisher()
	svc, users, _ := newAuditTestAuthService(t, auditPub)
	seedAuditPasswordUser(t, users, "user-1", "alice@example.com", "Passw0rd!")

	if err := svc.DeleteAccount(context.Background(), "user-1", "Passw0rd!"); err != nil {
		t.Fatalf("DeleteAccount: %v", err)
	}

	event := findEvent(auditPub.Events, audit.EventAccountDeleted)
	if event == nil {
		t.Fatalf("expected a user.account_deleted event, got %+v", auditPub.Events)
	}
	if event.ActorID == nil || *event.ActorID != "user-1" {
		t.Errorf("expected ActorID user-1, got %+v", event.ActorID)
	}
}

func TestConfirmDeleteAccount_PublishesAccountDeleted(t *testing.T) {
	auditPub := testutil.NewMockAuditPublisher()
	svc, users, _ := newAuditTestAuthService(t, auditPub)
	user := seedAuditPasswordUser(t, users, "user-1", "alice@example.com", "Passw0rd!")
	// ConfirmDeleteAccount requires the account to have no password — the
	// emailed-code path. Null the password hash after seeding.
	user.PasswordHash = nil
	if err := users.Update(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	mailer := &testutil.MockMailer{}
	svc.mailer = mailer
	if err := svc.RequestDeleteAccount(context.Background(), "user-1"); err != nil {
		t.Fatalf("RequestDeleteAccount: %v", err)
	}
	code := testutil.GetLastVerificationCode(mailer)
	if err := svc.ConfirmDeleteAccount(context.Background(), ConfirmDeleteAccountInput{
		UserID: "user-1", Code: code,
	}); err != nil {
		t.Fatalf("ConfirmDeleteAccount: %v", err)
	}

	event := findEvent(auditPub.Events, audit.EventAccountDeleted)
	if event == nil {
		t.Fatalf("expected a user.account_deleted event, got %+v", auditPub.Events)
	}
	if event.ActorID == nil || *event.ActorID != "user-1" {
		t.Errorf("expected ActorID user-1, got %+v", event.ActorID)
	}
}

func newAuditTestSessionService(auditPub *testutil.MockAuditPublisher) *SessionService {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	cfg := DefaultSessionConfig()
	cfg.Audit = auditPub
	return NewSessionService(sessions, gen, cfg)
}

func TestRevokeByIDForUser_PublishesSessionRevoked(t *testing.T) {
	auditPub := testutil.NewMockAuditPublisher()
	svc := newAuditTestSessionService(auditPub)

	created, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}

	ok, err := svc.RevokeByIDForUser(context.Background(), created.Session.ID, "user-1")
	if err != nil || !ok {
		t.Fatalf("RevokeByIDForUser = %v, %v", ok, err)
	}

	event := findEvent(auditPub.Events, audit.EventSessionRevoked)
	if event == nil {
		t.Fatalf("expected a session.revoked event, got %+v", auditPub.Events)
	}
	if event.ActorID == nil || *event.ActorID != "user-1" {
		t.Errorf("expected ActorID user-1, got %+v", event.ActorID)
	}
	if event.SessionID == nil || *event.SessionID != created.Session.ID {
		t.Errorf("expected SessionID %s, got %+v", created.Session.ID, event.SessionID)
	}
}

func TestRevokeByIDForUser_CrossUser_NoEvent(t *testing.T) {
	auditPub := testutil.NewMockAuditPublisher()
	svc := newAuditTestSessionService(auditPub)

	created, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}

	// Bob tries to revoke Alice's session: the repo reports ok=false (a
	// no-op), so no audit event must be published — that would let a
	// caller flood the audit log with failed probes.
	ok, err := svc.RevokeByIDForUser(context.Background(), created.Session.ID, "user-2")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("cross-user revoke must not succeed")
	}
	if findEvent(auditPub.Events, audit.EventSessionRevoked) != nil {
		t.Fatalf("no session.revoked event expected for failed revoke, got %+v", auditPub.Events)
	}
}

func TestRevokeManyForUser_PublishesOneRevokedEventWithCount(t *testing.T) {
	auditPub := testutil.NewMockAuditPublisher()
	svc := newAuditTestSessionService(auditPub)

	first, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}

	n, err := svc.RevokeManyForUser(context.Background(), []string{first.Session.ID, second.Session.ID}, "user-1")
	if err != nil || n != 2 {
		t.Fatalf("RevokeManyForUser = %d, %v", n, err)
	}

	event := findEvent(auditPub.Events, audit.EventSessionRevoked)
	if event == nil {
		t.Fatalf("expected a session.revoked event, got %+v", auditPub.Events)
	}
	if event.ActorID == nil || *event.ActorID != "user-1" {
		t.Errorf("expected ActorID user-1, got %+v", event.ActorID)
	}
	if event.Metadata["sessionCount"] != n {
		t.Errorf("expected metadata sessionCount=%d, got %+v", n, event.Metadata)
	}
}
