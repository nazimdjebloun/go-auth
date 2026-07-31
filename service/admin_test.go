package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func newTestAdminService(users *testutil.MockUserRepo, sessions *testutil.MockSessionRepo, hasher *testutil.MockHasher) *AdminService {
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	providers := testutil.NewMockProviderAccountRepo()
	return NewAdminService(users, sessions, providers, hasher, cfg, sessSvc)
}

// ─── ListUsers ─────────────────────────────────────────────────────

func TestAdminListUsers_Empty(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	result, err := svc.ListUsers(context.Background(), AdminListUsersInput{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Total != 0 {
		t.Fatalf("expected 0 users, got %d", result.Total)
	}
	if len(result.Users) != 0 {
		t.Fatalf("expected empty users slice, got %d", len(result.Users))
	}
}

func TestAdminListUsers_WithData(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	for i := range 5 {
		users.Create(context.Background(), &domain.User{
			ID:    "user-" + string(rune('a'+i)),
			Email: "user" + string(rune('a'+i)) + "@example.com",
			Name:  "User " + string(rune('A'+i)),
			Role:  domain.RoleUser,
		})
	}

	// MockUserRepo.List returns nil/0 by default; verify no error
	result, err := svc.ListUsers(context.Background(), AdminListUsersInput{Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Limit != 10 {
		t.Fatalf("expected limit 10, got %d", result.Limit)
	}
}

// ─── BanUser ───────────────────────────────────────────────────────

func TestAdminBanUser_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: false}
	users.Create(context.Background(), user)

	err := svc.BanUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	banned, _ := users.GetByID(context.Background(), "user-1")
	if !banned.IsBanned {
		t.Fatal("expected user to be banned")
	}
	if banned.BannedAt == nil {
		t.Fatal("expected BannedAt to be set")
	}
}

func TestAdminBanUser_NotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.BanUser(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", err.Code)
	}
}

func TestAdminBanUser_AlreadyBanned(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: true}
	users.Create(context.Background(), user)

	err := svc.BanUser(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "already_banned" {
		t.Fatalf("expected already_banned, got %s", err.Code)
	}
}

func TestAdminBanUser_RevokesSessions(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	session := &domain.Session{
		ID:     "session-1",
		UserID: "user-1",
	}
	sessions.Create(context.Background(), session)

	err := svc.BanUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessList, _ := sessions.ListAllByUserID(context.Background(), "user-1")
	if len(sessList) != 0 {
		t.Fatalf("expected 0 sessions after ban, got %d", len(sessList))
	}
}

// ─── UnbanUser ─────────────────────────────────────────────────────

func TestAdminUnbanUser_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	now := time.Now().UTC()
	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: true, BannedAt: &now}
	users.Create(context.Background(), user)

	err := svc.UnbanUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	unbanned, _ := users.GetByID(context.Background(), "user-1")
	if unbanned.IsBanned {
		t.Fatal("expected user to be unbanned")
	}
}

func TestAdminUnbanUser_NotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.UnbanUser(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", err.Code)
	}
}

func TestAdminUnbanUser_NotBanned(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: false}
	users.Create(context.Background(), user)

	err := svc.UnbanUser(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "not_banned" {
		t.Fatalf("expected not_banned, got %s", err.Code)
	}
}

// ─── UpdateUserRole ────────────────────────────────────────────────

func TestAdminUpdateUserRole_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", Role: domain.RoleUser}
	users.Create(context.Background(), user)

	err := svc.UpdateUserRole(context.Background(), "user-1", "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, _ := users.GetByID(context.Background(), "user-1")
	if updated.Role != domain.RoleAdmin {
		t.Fatalf("expected admin role, got %s", updated.Role)
	}
}

func TestAdminUpdateUserRole_NotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.UpdateUserRole(context.Background(), "nonexistent", "admin")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", err.Code)
	}
}

func TestAdminUpdateUserRole_InvalidRole(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", Role: domain.RoleUser}
	users.Create(context.Background(), user)

	err := svc.UpdateUserRole(context.Background(), "user-1", "superadmin")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "invalid_role" {
		t.Fatalf("expected invalid_role, got %s", err.Code)
	}
}

// ─── DeleteUser ────────────────────────────────────────────────────

func TestAdminDeleteUser_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	session := &domain.Session{
		ID:     "session-1",
		UserID: "user-1",
	}
	sessions.Create(context.Background(), session)

	err := svc.DeleteUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	deleted, _ := users.GetByID(context.Background(), "user-1")
	if deleted != nil {
		t.Fatal("expected user to be deleted")
	}

	sessList, _ := sessions.ListAllByUserID(context.Background(), "user-1")
	if len(sessList) != 0 {
		t.Fatal("expected sessions to be revoked after delete")
	}
}

func TestAdminDeleteUser_NotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.DeleteUser(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", err.Code)
	}
}

// ─── CreateUser ────────────────────────────────────────────────────

func TestAdminCreateUser_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user, err := svc.CreateUser(context.Background(), CreateUserInput{
		Email:    "new@example.com",
		Password: "Passw0rd!",
		Name:     "New User",
		Role:     "user",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Email != "new@example.com" {
		t.Fatalf("expected new@example.com, got %s", user.Email)
	}
	if user.Role != domain.RoleUser {
		t.Fatalf("expected user role, got %s", user.Role)
	}
	if !user.IsVerified {
		t.Fatal("expected user to be auto-verified")
	}
	if user.PasswordHash == nil {
		t.Fatal("expected password hash to be set")
	}
}

func TestAdminCreateUser_AdminRole(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user, err := svc.CreateUser(context.Background(), CreateUserInput{
		Email:    "admin@example.com",
		Password: "Passw0rd!",
		Name:     "Admin User",
		Role:     "admin",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Role != domain.RoleAdmin {
		t.Fatalf("expected admin role, got %s", user.Role)
	}
}

func TestAdminCreateUser_DuplicateEmail(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	svc.CreateUser(context.Background(), CreateUserInput{
		Email:    "dup@example.com",
		Password: "Passw0rd!",
		Name:     "User 1",
	})

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		Email:    "dup@example.com",
		Password: "Passw0rd!",
		Name:     "User 2",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "email_already_exists" {
		t.Fatalf("expected email_already_exists, got %s", err.Code)
	}
}

func TestAdminCreateUser_InvalidEmail(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		Email:    "not-an-email",
		Password: "Passw0rd!",
		Name:     "User",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAdminCreateUser_EmptyName(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "  ",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "name_required" {
		t.Fatalf("expected name_required, got %s", err.Code)
	}
}

func TestAdminCreateUser_WeakPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		Email:    "test@example.com",
		Password: "short",
		Name:     "User",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestAdminCreateUser_TrimmedLowercasedEmail(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user, err := svc.CreateUser(context.Background(), CreateUserInput{
		Email:    "  TEST@EXAMPLE.COM  ",
		Password: "Passw0rd!",
		Name:     "User",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Email != "test@example.com" {
		t.Fatalf("expected test@example.com, got %s", user.Email)
	}
}

// ─── ListUserSessions ──────────────────────────────────────────────

func TestAdminListUserSessions_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	sessions.Create(context.Background(), &domain.Session{ID: "sess-1", UserID: "user-1"})
	sessions.Create(context.Background(), &domain.Session{ID: "sess-2", UserID: "user-1"})

	result, _, err := svc.ListUserSessions(context.Background(), AdminListUserSessionsInput{
		UserID: "user-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(result))
	}
}

func TestAdminListUserSessions_NotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	_, _, err := svc.ListUserSessions(context.Background(), AdminListUserSessionsInput{
		UserID: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", err.Code)
	}
}

func TestAdminListUserSessions_WithOffsetLimit(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	for i := range 5 {
		sessions.Create(context.Background(), &domain.Session{
			ID:     "sess-" + string(rune('0'+i)),
			UserID: "user-1",
		})
	}

	result, _, err := svc.ListUserSessions(context.Background(), AdminListUserSessionsInput{
		UserID: "user-1",
		Offset: 1,
		Limit:  2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(result))
	}
}

func TestAdminListUserSessions_EmptyResult(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	result, _, err := svc.ListUserSessions(context.Background(), AdminListUserSessionsInput{
		UserID: "user-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(result))
	}
}

// ─── RevokeUserSession ─────────────────────────────────────────────

func TestAdminRevokeUserSession_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	sessions.Create(context.Background(), &domain.Session{ID: "sess-1", UserID: "user-1"})

	err := svc.RevokeUserSession(context.Background(), "user-1", "sess-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessList, _ := sessions.ListAllByUserID(context.Background(), "user-1")
	if len(sessList) != 0 {
		t.Fatalf("expected 0 sessions after revoke, got %d", len(sessList))
	}
}

func TestAdminRevokeUserSession_NotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	err := svc.RevokeUserSession(context.Background(), "user-1", "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "session_not_found" {
		t.Fatalf("expected session_not_found, got %s", err.Code)
	}
}

func TestAdminRevokeUserSession_UserNotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.RevokeUserSession(context.Background(), "nonexistent", "sess-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", err.Code)
	}
}

// ─── RevokeUserSessions ────────────────────────────────────────────

func TestAdminRevokeUserSessions_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	sessions.Create(context.Background(), &domain.Session{ID: "sess-1", UserID: "user-1"})
	sessions.Create(context.Background(), &domain.Session{ID: "sess-2", UserID: "user-1"})

	err := svc.RevokeUserSessions(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessList, _ := sessions.ListAllByUserID(context.Background(), "user-1")
	if len(sessList) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessList))
	}
}

func TestAdminRevokeUserSessions_NotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.RevokeUserSessions(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", err.Code)
	}
}
