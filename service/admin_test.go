package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

// newTestAdminService also seeds and returns an admin actor's ID — every
// AdminService method requires one now, so tests use this as the caller.
func newTestAdminService(users *testutil.MockUserRepo, sessions *testutil.MockSessionRepo, hasher *testutil.MockHasher) (*AdminService, string) {
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, testutil.NewMockAuditLogRepo(), hasher)
	return svc, actorID
}

// newTestAdminServiceWithAudit is newTestAdminService plus an explicit,
// caller-supplied audit log mock — for GetStats/GetRegistrationTrend/
// GetLoginActivity tests that need to seed audit rows into the exact
// instance the service under test reads from.
func newTestAdminServiceWithAudit(users *testutil.MockUserRepo, sessions *testutil.MockSessionRepo, auditLogs *testutil.MockAuditLogRepo, hasher *testutil.MockHasher) (*AdminService, string, *testutil.MockAuditLogRepo) {
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	providers := testutil.NewMockProviderAccountRepo()
	actor := &domain.User{ID: "actor-admin", Email: "actor-admin@example.com", Role: domain.RoleAdmin}
	users.Create(context.Background(), actor)
	return NewAdminService(users, sessions, providers, auditLogs, hasher, cfg, sessSvc), actor.ID, auditLogs
}

// ─── ListUsers ─────────────────────────────────────────────────────

func TestAdminListUsers_Empty(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	result, err := svc.ListUsers(context.Background(), AdminListUsersInput{
		ActorID: actorID, Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	// newTestAdminService seeds one user — the admin actor itself.
	if result.Total != 1 {
		t.Fatalf("expected 1 user, got %d", result.Total)
	}
	if len(result.Users) != 1 {
		t.Fatalf("expected 1 user in slice, got %d", len(result.Users))
	}
}

func TestAdminListUsers_WithData(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	for i := range 5 {
		users.Create(context.Background(), &domain.User{
			ID:    "user-" + string(rune('a'+i)),
			Email: "user" + string(rune('a'+i)) + "@example.com",
			Name:  "User " + string(rune('A'+i)),
			Role:  domain.RoleUser,
		})
	}

	result, err := svc.ListUsers(context.Background(), AdminListUsersInput{
		ActorID: actorID, Limit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.Limit != 10 {
		t.Fatalf("expected limit 10, got %d", result.Limit)
	}
	// 5 seeded users plus newTestAdminService's own actor-admin.
	if result.Total != 6 {
		t.Fatalf("expected 6 users, got %d", result.Total)
	}
}

// ─── BanUser ───────────────────────────────────────────────────────

func TestAdminBanUser_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: false}
	users.Create(context.Background(), user)

	err := svc.BanUser(context.Background(), BanUserInput{UserID: "user-1", ActorID: actorID})
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.BanUser(context.Background(), BanUserInput{UserID: "nonexistent", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
	}
}

func TestAdminBanUser_AlreadyBanned(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: true}
	users.Create(context.Background(), user)

	err := svc.BanUser(context.Background(), BanUserInput{UserID: "user-1", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "already_banned" {
		t.Fatalf("expected already_banned, got %s", authErrCode(err))
	}
}

func TestAdminBanUser_RevokesSessions(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	session := &domain.Session{
		ID:     "session-1",
		UserID: "user-1",
	}
	sessions.Create(context.Background(), session)

	err := svc.BanUser(context.Background(), BanUserInput{UserID: "user-1", ActorID: actorID})
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	now := time.Now().UTC()
	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: true, BannedAt: &now}
	users.Create(context.Background(), user)

	err := svc.UnbanUser(context.Background(), UnbanUserInput{UserID: "user-1", ActorID: actorID})
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.UnbanUser(context.Background(), UnbanUserInput{UserID: "nonexistent", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
	}
}

func TestAdminUnbanUser_NotBanned(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: false}
	users.Create(context.Background(), user)

	err := svc.UnbanUser(context.Background(), UnbanUserInput{UserID: "user-1", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "not_banned" {
		t.Fatalf("expected not_banned, got %s", authErrCode(err))
	}
}

// ─── UpdateUserRole ────────────────────────────────────────────────

func TestAdminUpdateUserRole_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", Role: domain.RoleUser}
	users.Create(context.Background(), user)

	err := svc.UpdateUserRole(context.Background(), UpdateUserRoleInput{UserID: "user-1", Role: "admin", ActorID: actorID})
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.UpdateUserRole(context.Background(), UpdateUserRoleInput{UserID: "nonexistent", Role: "admin", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
	}
}

func TestAdminUpdateUserRole_InvalidRole(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com", Role: domain.RoleUser}
	users.Create(context.Background(), user)

	err := svc.UpdateUserRole(context.Background(), UpdateUserRoleInput{UserID: "user-1", Role: "superadmin", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "invalid_role" {
		t.Fatalf("expected invalid_role, got %s", authErrCode(err))
	}
}

// ─── DeleteUser ────────────────────────────────────────────────────

func TestAdminDeleteUser_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	session := &domain.Session{
		ID:     "session-1",
		UserID: "user-1",
	}
	sessions.Create(context.Background(), session)

	err := svc.DeleteUser(context.Background(), DeleteUserInput{UserID: "user-1", ActorID: actorID})
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.DeleteUser(context.Background(), DeleteUserInput{UserID: "nonexistent", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
	}
}

// ─── CreateUser ────────────────────────────────────────────────────

func TestAdminCreateUser_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user, err := svc.CreateUser(context.Background(), CreateUserInput{
		ActorID:  actorID,
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user, err := svc.CreateUser(context.Background(), CreateUserInput{
		ActorID:  actorID,
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	svc.CreateUser(context.Background(), CreateUserInput{
		ActorID:  actorID,
		Email:    "dup@example.com",
		Password: "Passw0rd!",
		Name:     "User 1",
	})

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		ActorID:  actorID,
		Email:    "dup@example.com",
		Password: "Passw0rd!",
		Name:     "User 2",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "email_already_exists" {
		t.Fatalf("expected email_already_exists, got %s", authErrCode(err))
	}
}

func TestAdminCreateUser_InvalidEmail(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		ActorID:  actorID,
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		ActorID:  actorID,
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "  ",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "name_required" {
		t.Fatalf("expected name_required, got %s", authErrCode(err))
	}
}

func TestAdminCreateUser_WeakPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		ActorID:  actorID,
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user, err := svc.CreateUser(context.Background(), CreateUserInput{
		ActorID:  actorID,
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	sessions.Create(context.Background(), &domain.Session{ID: "sess-1", UserID: "user-1"})
	sessions.Create(context.Background(), &domain.Session{ID: "sess-2", UserID: "user-1"})

	result, _, err := svc.ListUserSessions(context.Background(), AdminListUserSessionsInput{
		ActorID: actorID,
		UserID:  "user-1",
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	_, _, err := svc.ListUserSessions(context.Background(), AdminListUserSessionsInput{
		ActorID: actorID,
		UserID:  "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
	}
}

func TestAdminListUserSessions_WithOffsetLimit(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	for i := range 5 {
		sessions.Create(context.Background(), &domain.Session{
			ID:     "sess-" + string(rune('0'+i)),
			UserID: "user-1",
		})
	}

	result, _, err := svc.ListUserSessions(context.Background(), AdminListUserSessionsInput{
		ActorID: actorID,
		UserID:  "user-1",
		Offset:  1,
		Limit:   2,
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	result, _, err := svc.ListUserSessions(context.Background(), AdminListUserSessionsInput{
		ActorID: actorID,
		UserID:  "user-1",
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	sessions.Create(context.Background(), &domain.Session{ID: "sess-1", UserID: "user-1"})

	err := svc.RevokeUserSession(context.Background(), RevokeUserSessionInput{UserID: "user-1", SessionID: "sess-1", ActorID: actorID})
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	err := svc.RevokeUserSession(context.Background(), RevokeUserSessionInput{UserID: "user-1", SessionID: "nonexistent", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "session_not_found" {
		t.Fatalf("expected session_not_found, got %s", authErrCode(err))
	}
}

func TestAdminRevokeUserSession_UserNotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.RevokeUserSession(context.Background(), RevokeUserSessionInput{UserID: "nonexistent", SessionID: "sess-1", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
	}
}

// ─── RevokeUserSessions ────────────────────────────────────────────

func TestAdminRevokeUserSessions_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(context.Background(), user)

	sessions.Create(context.Background(), &domain.Session{ID: "sess-1", UserID: "user-1"})
	sessions.Create(context.Background(), &domain.Session{ID: "sess-2", UserID: "user-1"})

	err := svc.RevokeUserSessions(context.Background(), RevokeUserSessionsInput{UserID: "user-1", ActorID: actorID})
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
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	err := svc.RevokeUserSessions(context.Background(), RevokeUserSessionsInput{UserID: "nonexistent", ActorID: actorID})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
	}
}

// ─── Actor authorization ───────────────────────────────────────────
//
// Every AdminService method requires an ActorID that resolves to a current
// domain.RoleAdmin user — these mirror the HTTP layer's
// RequireRole(domain.RoleAdmin) middleware, but are the real authority: they
// also protect auth.Services.Admin.* called directly, with no HTTP in front.

func TestAdminBanUser_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	users.Create(context.Background(), nonAdmin)
	target := &domain.User{ID: "user-1", Email: "target@example.com"}
	users.Create(context.Background(), target)

	err := svc.BanUser(context.Background(), BanUserInput{UserID: "user-1", ActorID: "not-admin"})
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestAdminBanUser_ActorMissing_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	target := &domain.User{ID: "user-1", Email: "target@example.com"}
	users.Create(context.Background(), target)

	err := svc.BanUser(context.Background(), BanUserInput{UserID: "user-1", ActorID: ""})
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestAdminDeleteUser_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	users.Create(context.Background(), nonAdmin)
	target := &domain.User{ID: "user-1", Email: "target@example.com"}
	users.Create(context.Background(), target)

	err := svc.DeleteUser(context.Background(), DeleteUserInput{UserID: "user-1", ActorID: "not-admin"})
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestAdminCreateUser_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	users.Create(context.Background(), nonAdmin)

	_, err := svc.CreateUser(context.Background(), CreateUserInput{
		ActorID: "not-admin", Email: "new@example.com", Password: "Passw0rd!", Name: "New",
	})
	if err != domain.ErrForbidden {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

// ─── ListUsers dormancy filters ─────────────────────────────────────

func TestAdminListUsers_NeverLoggedIn(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	loggedIn := time.Now().UTC()
	users.Create(context.Background(), &domain.User{ID: "u1", Email: "u1@example.com", LastLoginAt: &loggedIn})
	users.Create(context.Background(), &domain.User{ID: "u2", Email: "u2@example.com"})

	yes := true
	result, err := svc.ListUsers(context.Background(), AdminListUsersInput{
		ActorID: actorID, Limit: 10, NeverLoggedIn: &yes,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// u2 plus newTestAdminService's own actor-admin — neither has logged in.
	if result.Total != 2 {
		t.Fatalf("expected 2 never-logged-in users, got %d", result.Total)
	}
	for _, u := range result.Users {
		if u.ID == "u1" {
			t.Error("expected u1 (has logged in) to be excluded")
		}
	}
}

func TestAdminListUsers_LastLoginBefore(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, actorID := newTestAdminService(users, sessions, &testutil.MockHasher{})

	cutoff := time.Now().UTC()
	dormantSince := cutoff.Add(-30 * 24 * time.Hour)
	stillActive := cutoff.Add(1 * time.Hour) // logged in *after* cutoff
	users.Create(context.Background(), &domain.User{ID: "dormant", Email: "dormant@example.com", LastLoginAt: &dormantSince})
	users.Create(context.Background(), &domain.User{ID: "active", Email: "active@example.com", LastLoginAt: &stillActive})
	users.Create(context.Background(), &domain.User{ID: "never", Email: "never@example.com"})

	result, err := svc.ListUsers(context.Background(), AdminListUsersInput{
		ActorID: actorID, Limit: 10, LastLoginBefore: &cutoff,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only "dormant" logged in before cutoff — "active" logged in after it,
	// "never" and the actor-admin have never logged in (LastLoginBefore
	// excludes NULLs, that's NeverLoggedIn's job).
	if result.Total != 1 {
		t.Fatalf("expected 1 dormant user, got %d", result.Total)
	}
	if len(result.Users) != 1 || result.Users[0].ID != "dormant" {
		t.Errorf("expected only 'dormant' user, got %+v", result.Users)
	}
}

// ─── GetStats ────────────────────────────────────────────────────────

func TestGetStats_ActorNotAdmin_Forbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	svc, _ := newTestAdminService(users, sessions, &testutil.MockHasher{})

	nonAdmin := &domain.User{ID: "not-admin", Email: "not-admin@example.com", Role: domain.RoleUser}
	users.Create(context.Background(), nonAdmin)

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
	users.Create(context.Background(), &domain.User{ID: "u1", Email: "u1@example.com", IsVerified: true, LastLoginAt: &loggedIn})
	users.Create(context.Background(), &domain.User{ID: "u2", Email: "u2@example.com", IsBanned: true})
	users.Create(context.Background(), &domain.User{ID: "u3", Email: "u3@example.com", TwoFactorEnabled: true})

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
	users.Create(context.Background(), nonAdmin)

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
	users.Create(context.Background(), &domain.User{ID: "u1", Email: "u1@example.com", CreatedAt: today})
	users.Create(context.Background(), &domain.User{ID: "u2", Email: "u2@example.com", CreatedAt: yesterday})

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
	users.Create(context.Background(), nonAdmin)

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
