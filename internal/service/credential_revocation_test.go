package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

var errInjectedRevocationAfterDelete = errors.New("test: revocation failed after deleting sessions")

type failingAfterDeleteSessions struct {
	port.SessionRepository
}

func (s *failingAfterDeleteSessions) DeleteAllForUser(ctx context.Context, userID string) error {
	if err := s.SessionRepository.DeleteAllForUser(ctx, userID); err != nil {
		return err
	}
	return errInjectedRevocationAfterDelete
}

func (s *failingAfterDeleteSessions) DeleteAllForUserExcept(ctx context.Context, userID, exceptID string) error {
	if err := s.SessionRepository.DeleteAllForUserExcept(ctx, userID, exceptID); err != nil {
		return err
	}
	return errInjectedRevocationAfterDelete
}

func TestBanUser_RevocationFailureRollsBackBanAndSessions(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const actorID = "00000000-0000-4000-8000-000000000030"
	if err := f.users.Create(ctx, &domain.User{
		ID: actorID, Email: "ban-actor@example.com", Name: "Admin",
		Role: domain.RoleAdmin, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	sessions := &failingAfterDeleteSessions{SessionRepository: f.sessions}
	sessionSvc := NewSessionService(f.db, sessions, nil, DefaultSessionConfig())
	svc := NewAdminService(f.db, f.users, sessions, nil, nil, f.hasher, defaultTestConfig(), sessionSvc)

	if err := svc.BanUser(ctx, api.BanUserInput{UserID: f.userID, ActorID: actorID}); !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("BanUser error = %v, want internal_error", err)
	}
	user, err := f.users.GetByID(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.IsBanned || user.BannedAt != nil {
		t.Fatal("revocation failure committed the ban")
	}
	session, err := f.sessions.GetByTokenHash(ctx, f.session)
	if err != nil {
		t.Fatal(err)
	}
	if session == nil {
		t.Fatal("revocation failure deleted the existing session")
	}
}

func TestEnableTwoFactor_RevocationFailureRollsBackFlagAndSessions(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	ctx := context.Background()
	sessions := &failingAfterDeleteSessions{SessionRepository: f.sessions}
	svc := NewTwoFactorService(f.db, f.users, sessions, f.tokens, f.hasher, nil, nil, defaultTestConfig(), nil)

	if err := svc.Enable(ctx, f.userID, "OldPass1!", false, "other-caller-session"); !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("Enable error = %v, want internal_error", err)
	}
	user, err := f.users.GetByID(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.TwoFactorEnabled {
		t.Fatal("revocation failure committed the two-factor flag")
	}
	session, err := f.sessions.GetByTokenHash(ctx, f.session)
	if err != nil {
		t.Fatal(err)
	}
	if session == nil {
		t.Fatal("revocation failure deleted the existing session")
	}
}

// failingAuditPublisher models the fail-closed enqueue mode: Record always
// fails, which is what must roll the state change back when the two share a
// transaction.
type failingAuditPublisher struct{}

var errInjectedAuditFailure = errors.New("test: audit record failed under fail-closed")

func (failingAuditPublisher) Record(context.Context, audit.Event) error {
	return errInjectedAuditFailure
}

func TestUnbanUser_AuditFailureRollsBackUnban(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	const actorID = "00000000-0000-4000-8000-000000000031"
	if err := f.users.Create(ctx, &domain.User{
		ID: actorID, Email: "unban-actor@example.com", Name: "Admin",
		Role: domain.RoleAdmin, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.users.SetBanStatus(ctx, f.userID, true, &now, now); err != nil {
		t.Fatal(err)
	}
	cfg := defaultTestConfig()
	cfg.Audit = failingAuditPublisher{}
	svc := NewAdminService(f.db, f.users, f.sessions, nil, nil, f.hasher, cfg, nil)

	if err := svc.UnbanUser(ctx, api.UnbanUserInput{UserID: f.userID, ActorID: actorID}); !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("UnbanUser error = %v, want internal_error", err)
	}
	user, err := f.users.GetByID(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if !user.IsBanned {
		t.Fatal("audit failure committed the unban")
	}
}

func TestDisableTwoFactor_AuditFailureRollsBackFlag(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	ctx := context.Background()
	if err := f.users.SetTwoFactorEnabled(ctx, f.userID, true, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	cfg := defaultTestConfig()
	cfg.Audit = failingAuditPublisher{}
	svc := NewTwoFactorService(f.db, f.users, f.sessions, f.tokens, f.hasher, nil, nil, cfg, nil)

	if err := svc.Disable(ctx, f.userID, "OldPass1!"); !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("Disable error = %v, want internal_error", err)
	}
	user, err := f.users.GetByID(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if !user.TwoFactorEnabled {
		t.Fatal("audit failure committed the 2FA disable")
	}
}
