package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

// ─── ListSessions ────────────────────────────────────────────────────

func seedSession(t *testing.T, sessions *testutil.MockSessionRepo, id, userID, ip string) {
	t.Helper()
	now := time.Now().UTC()
	if err := sessions.Create(context.Background(), &domain.Session{
		ID: id, UserID: userID, TokenHash: id + "-token", RefreshTokenHash: id + "-refresh",
		IP: ip, UserAgent: "test-agent", ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seedSession: %v", err)
	}
}

func TestAdminListSessions_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	seedSession(t, sessions, "s1", "user-1", "1.1.1.1")
	seedSession(t, sessions, "s2", "user-2", "2.2.2.2")

	result, err := svc.ListSessions(context.Background(), api.AdminListSessionsInput{ActorID: actorID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(result.Sessions))
	}
}

func TestAdminListSessions_FilterByUserID(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	seedSession(t, sessions, "s1", "user-1", "1.1.1.1")
	seedSession(t, sessions, "s2", "user-2", "2.2.2.2")

	userID := "user-1"
	result, err := svc.ListSessions(context.Background(), api.AdminListSessionsInput{ActorID: actorID, UserID: &userID})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Sessions) != 1 || result.Sessions[0].UserID != "user-1" {
		t.Fatalf("expected 1 session for user-1, got %+v", result)
	}
}

func TestAdminListSessions_FilterByIP(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	seedSession(t, sessions, "s1", "user-1", "1.1.1.1")
	seedSession(t, sessions, "s2", "user-2", "2.2.2.2")

	ip := "2.2.2.2"
	result, err := svc.ListSessions(context.Background(), api.AdminListSessionsInput{ActorID: actorID, IP: &ip})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Sessions) != 1 || result.Sessions[0].UserID != "user-2" {
		t.Fatalf("expected 1 session for user-2, got %+v", result)
	}
}

func TestAdminListSessions_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	checkTestErrors(t).noError(users.Create(context.Background(), nonAdmin))

	_, err := svc.ListSessions(context.Background(), api.AdminListSessionsInput{ActorID: "not-admin"})
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}
