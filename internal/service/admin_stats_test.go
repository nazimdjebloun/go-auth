package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

// ─── GetStats ────────────────────────────────────────────────────────

func TestGetStats_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	checkTestErrors(t).noError(users.Create(context.Background(), nonAdmin))

	_, err := svc.GetStats(context.Background(), "not-admin")
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestGetStats_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	loggedIn := time.Now().UTC()
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{ID: "u1", Email: "u1@example.com", IsVerified: true, LastLoginAt: &loggedIn}))
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{ID: "u2", Email: "u2@example.com", IsBanned: true}))
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{ID: "u3", Email: "u3@example.com", TwoFactorEnabled: true}))

	stats, err := svc.GetStats(context.Background(), actorID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.TotalUsers != 4 { // actor-admin + u1 + u2 + u3
		t.Errorf("expected 4 total users, got %d", stats.TotalUsers)
	}
	if stats.VerifiedUsers != 1 {
		t.Errorf("expected 1 verified user, got %d", stats.VerifiedUsers)
	}
	if stats.BannedUsers != 1 {
		t.Errorf("expected 1 banned user, got %d", stats.BannedUsers)
	}
	if stats.TwoFactorEnabledUsers != 1 {
		t.Errorf("expected 1 two-factor user, got %d", stats.TwoFactorEnabledUsers)
	}
	if stats.NeverLoggedInUsers != 3 { // actor-admin + u2 + u3
		t.Errorf("expected 3 never-logged-in users, got %d", stats.NeverLoggedInUsers)
	}
}

// ─── GetRegistrationTrend ────────────────────────────────────────────

func TestGetRegistrationTrend_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	checkTestErrors(t).noError(users.Create(context.Background(), nonAdmin))

	_, err := svc.GetRegistrationTrend(context.Background(), StatsRangeInput{
		ActorID: "not-admin", From: time.Now().Add(-time.Hour), To: time.Now(),
	})
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestGetRegistrationTrend_InvalidRange(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	now := time.Now().UTC()
	_, err := svc.GetRegistrationTrend(context.Background(), StatsRangeInput{
		ActorID: actorID, From: now, To: now.Add(-time.Hour), // to before from
	})
	authErr, ok := err.(*domain.AuthError)
	if !ok || authErr.Code != "invalid_input" {
		t.Errorf("expected invalid_input error, got %v", err)
	}
}

func TestGetRegistrationTrend_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	today := time.Now().UTC()
	yesterday := today.Add(-24 * time.Hour)
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{ID: "u1", Email: "u1@example.com", CreatedAt: today}))
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{ID: "u2", Email: "u2@example.com", CreatedAt: yesterday}))

	counts, err := svc.GetRegistrationTrend(context.Background(), StatsRangeInput{
		ActorID: actorID, From: yesterday.Add(-time.Hour), To: today.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var total int
	for _, c := range counts {
		total += c.Count
	}
	if total != 2 {
		t.Errorf("expected 2 registrations across buckets, got %d (%+v)", total, counts)
	}
}

// ─── GetLoginActivity ────────────────────────────────────────────────

func TestGetLoginActivity_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	checkTestErrors(t).noError(users.Create(context.Background(), nonAdmin))

	_, err := svc.GetLoginActivity(context.Background(), LoginActivityInput{
		ActorID: "not-admin", From: time.Now().Add(-time.Hour), To: time.Now(),
	})
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestGetLoginActivity_Global(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})

	now := time.Now().UTC()
	alice, bob := "alice", "bob"
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", ActorID: &alice, CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", ActorID: &bob, CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e3", Type: "login.failed", ActorID: &alice, CreatedAt: now})

	counts, err := svc.GetLoginActivity(context.Background(), LoginActivityInput{
		ActorID: actorID, From: now.Add(-time.Hour), To: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var total int
	for _, c := range counts {
		total += c.Count
	}
	if total != 2 {
		t.Errorf("expected 2 successful logins, got %d (%+v)", total, counts)
	}
}

func TestGetLoginActivity_PerUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	auditLogs := testutil.NewMockAuditLogRepo()
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, auditLogs, &testutil.MockHasher{})

	now := time.Now().UTC()
	alice, bob := "alice", "bob"
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", ActorID: &alice, CreatedAt: now})
	auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", ActorID: &bob, CreatedAt: now})

	counts, err := svc.GetLoginActivity(context.Background(), LoginActivityInput{
		ActorID: actorID, UserID: &alice, From: now.Add(-time.Hour), To: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var total int
	for _, c := range counts {
		total += c.Count
	}
	if total != 1 {
		t.Errorf("expected 1 login for alice, got %d (%+v)", total, counts)
	}
}
