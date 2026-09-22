package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

// ─── Bulk user actions ─────────────────────────────────────────────

func TestBulkBanUsers_PartialFailure(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	users.Create(context.Background(), &domain.User{ID: "user-1", Email: "u1@example.com"})
	users.Create(context.Background(), &domain.User{ID: "user-2", Email: "u2@example.com"})

	result, err := svc.BulkBanUsers(context.Background(), BulkUserActionInput{
		UserIDs: []string{"user-1", "user-2", "nonexistent"}, ActorID: actorID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Succeeded) != 2 {
		t.Fatalf("expected 2 succeeded, got %+v", result.Succeeded)
	}
	if len(result.Failed) != 1 || result.Failed[0].UserID != "nonexistent" || result.Failed[0].Code != "user_not_found" {
		t.Fatalf("expected 1 failure for nonexistent/user_not_found, got %+v", result.Failed)
	}

	u1, _ := users.GetByID(context.Background(), "user-1")
	if !u1.IsBanned {
		t.Error("expected user-1 to be banned")
	}
}

func TestBulkBanUsers_EmptyInput_Error(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	_, err := svc.BulkBanUsers(context.Background(), BulkUserActionInput{UserIDs: nil, ActorID: actorID})
	if authErrCode(err) != "invalid_input" {
		t.Fatalf("expected invalid_input, got %v", err)
	}
}

func TestBulkBanUsers_TooMany_Error(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	ids := make([]string, maxBulkUserIDs+1)
	for i := range ids {
		ids[i] = "user-" + string(rune('a'+i%26))
	}
	_, err := svc.BulkBanUsers(context.Background(), BulkUserActionInput{UserIDs: ids, ActorID: actorID})
	if authErrCode(err) != "invalid_input" {
		t.Fatalf("expected invalid_input, got %v", err)
	}
}

func TestBulkBanUsers_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	users.Create(context.Background(), nonAdmin)

	_, err := svc.BulkBanUsers(context.Background(), BulkUserActionInput{UserIDs: []string{"user-1"}, ActorID: "not-admin"})
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestBulkUnbanUsers_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	now := time.Now().UTC()
	users.Create(context.Background(), &domain.User{ID: "user-1", Email: "u1@example.com", IsBanned: true, BannedAt: &now})
	users.Create(context.Background(), &domain.User{ID: "user-2", Email: "u2@example.com", IsBanned: true, BannedAt: &now})

	result, err := svc.BulkUnbanUsers(context.Background(), BulkUserActionInput{
		UserIDs: []string{"user-1", "user-2"}, ActorID: actorID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Succeeded) != 2 || len(result.Failed) != 0 {
		t.Fatalf("expected both to succeed, got %+v", result)
	}
}

func TestBulkDeleteUsers_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	users.Create(context.Background(), &domain.User{ID: "user-1", Email: "u1@example.com"})
	users.Create(context.Background(), &domain.User{ID: "user-2", Email: "u2@example.com"})

	result, err := svc.BulkDeleteUsers(context.Background(), BulkUserActionInput{
		UserIDs: []string{"user-1", "user-2"}, ActorID: actorID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Succeeded) != 2 || len(result.Failed) != 0 {
		t.Fatalf("expected both to succeed, got %+v", result)
	}
	if u, _ := users.GetByID(context.Background(), "user-1"); u != nil {
		t.Error("expected user-1 to be deleted")
	}
}

func TestBulkRevokeUserSessions_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	users.Create(context.Background(), &domain.User{ID: "user-1", Email: "u1@example.com"})
	seedSession(t, sessions, "s1", "user-1", "1.1.1.1")

	result, err := svc.BulkRevokeUserSessions(context.Background(), BulkUserActionInput{
		UserIDs: []string{"user-1"}, ActorID: actorID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Succeeded) != 1 {
		t.Fatalf("expected 1 succeeded, got %+v", result)
	}
	active, _, err := sessions.ListByUserID(context.Background(), "user-1", 0, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(active) != 0 {
		t.Fatalf("expected sessions revoked, got %d active", len(active))
	}
}
