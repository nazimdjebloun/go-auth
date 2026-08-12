package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestRegister(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	result, err := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "Test User",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.User.Email != "test@example.com" {
		t.Fatalf("Expected email test@example.com, got %s", result.User.Email)
	}
	if result.Session == nil {
		t.Fatal("Expected session, got nil")
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
	if result.User.Role != domain.RoleUser {
		t.Fatalf("Expected role user, got %s", result.User.Role)
	}
}

func TestRegisterDuplicateEmail(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "Test",
	})

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "Test 2",
	})
	if err == nil {
		t.Fatal("Expected error for duplicate email, got nil")
	}
	if authErrCode(err) != "email_already_exists" {
		t.Fatalf("Expected email_already_exists, got %s", authErrCode(err))
	}
}

func TestRegisterWeakPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "short",
		Name:     "Test",
	})
	if err == nil {
		t.Fatal("Expected error for weak password, got nil")
	}
}

func TestRegisterInvalidEmail(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "not-an-email",
		Password: "Passw0rd!",
		Name:     "Test",
	})
	if err == nil {
		t.Fatal("Expected error for invalid email, got nil")
	}
}

func TestRegisterDefaultRole(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	result, err := svc.Register(context.Background(), RegisterInput{
		Email:    "registered@example.com",
		Password: "Passw0rd!",
		Name:     "User",
	})
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if result.User.Role != domain.RoleUser {
		t.Fatalf("Expected role user, got %s", result.User.Role)
	}
}

func TestRegisterInviteOnly(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	cfg := defaultTestConfig()
	cfg.InviteOnly = true

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg, sessSvc, nil, nil)

	_, err := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "Test",
	})
	if err == nil {
		t.Fatal("Expected error for invite-only mode, got nil")
	}
}

func TestLogin(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	regResult, _ := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "Test",
	})

	regResult.User.IsVerified = true
	users.Update(context.Background(), regResult.User)

	result, err := svc.Login(context.Background(), LoginInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		IP:       "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
}

func TestLoginWrongPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	regResult, _ := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "Test",
	})

	regResult.User.IsVerified = true
	users.Update(context.Background(), regResult.User)

	_, err := svc.Login(context.Background(), LoginInput{
		Email:    "test@example.com",
		Password: "wrongpassword",
	})
	if err == nil {
		t.Fatal("Expected error for wrong password, got nil")
	}
}

func TestLoginNonexistentUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	_, err := svc.Login(context.Background(), LoginInput{
		Email:    "nobody@example.com",
		Password: "Passw0rd!",
	})
	if err == nil {
		t.Fatal("Expected error for nonexistent user, got nil")
	}
}

func TestLoginUnverifiedUser_WithVerificationDisabled(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	cfg := defaultTestConfig()
	cfg.RequireEmailVerification = false

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg, sessSvc, nil, nil)

	regResult, _ := svc.Register(context.Background(), RegisterInput{
		Email:    "unverified@example.com",
		Password: "Passw0rd!",
		Name:     "Test",
	})
	if regResult.User.IsVerified {
		t.Fatal("Expected user to remain unverified after register with RequireEmailVerification=false")
	}

	result, err := svc.Login(context.Background(), LoginInput{
		Email:    "unverified@example.com",
		Password: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("Login should succeed when RequireEmailVerification is false: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
}

func TestLoginUnverifiedUser_WithVerificationEnabled(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	cfg := defaultTestConfig()
	cfg.RequireEmailVerification = true

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg, sessSvc, nil, nil)

	// Directly create an unverified user (Register would call SendVerification and fail with nil mailer)
	hash, _ := hasher.Hash("Passw0rd!")
	users.Create(context.Background(), &domain.User{
		ID:           "unverified-user-id",
		Email:        "unverified@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		Role:         domain.RoleUser,
		IsVerified:   false,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	result, err := svc.Login(context.Background(), LoginInput{
		Email:    "unverified@example.com",
		Password: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !result.RequiresVerification {
		t.Fatal("Expected RequiresVerification to be true")
	}
	if result.Session != nil {
		t.Fatal("Expected no session for unverified user")
	}
	if result.User == nil {
		t.Fatal("Expected user to be returned")
	}
}

func TestLogout(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	result, _ := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "Test",
	})

	err := svc.Logout(context.Background(), result.Session.ID)
	if err != nil {
		t.Fatalf("Logout failed: %v", err)
	}

	_, _, err = svc.ValidateSession(context.Background(), result.SessionToken)
	if err == nil {
		t.Fatal("Expected session to be invalid after logout")
	}
}

func TestDeleteAccount_PasswordRequired(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)

	oauthUser := &domain.User{
		ID:        "oauth-user-id",
		Email:     "oauth@example.com",
		Name:      "OAuth User",
		Role:      domain.RoleUser,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	users.Create(context.Background(), oauthUser)

	err := svc.DeleteAccount(context.Background(), oauthUser.ID, "")
	if err == nil {
		t.Fatal("Expected error for OAuth-only user, got nil")
	}
	if authErrCode(err) != "password_required" {
		t.Fatalf("Expected password_required, got %s", authErrCode(err))
	}
}

func TestRequestDeleteAccount_Success(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	mailer := &testutil.MockMailer{}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, mailer, defaultTestConfig(), sessSvc, nil, nil)

	oauthUser := &domain.User{
		ID:        "oauth-user-id",
		Email:     "oauth@example.com",
		Name:      "OAuth User",
		Role:      domain.RoleUser,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	users.Create(context.Background(), oauthUser)

	err := svc.RequestDeleteAccount(context.Background(), oauthUser.ID)
	if err != nil {
		t.Fatalf("RequestDeleteAccount failed: %v", err)
	}

	if len(mailer.Calls) != 1 {
		t.Fatalf("Expected 1 email call, got %d", len(mailer.Calls))
	}
	if mailer.Calls[0].To != "oauth@example.com" {
		t.Fatalf("Expected email to oauth@example.com, got %s", mailer.Calls[0].To)
	}
}

func TestRequestDeleteAccount_PasswordUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	mailer := &testutil.MockMailer{}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, mailer, defaultTestConfig(), sessSvc, nil, nil)

	hash, _ := hasher.Hash("Passw0rd!")
	passwordUser := &domain.User{
		ID:           "password-user-id",
		Email:        "password@example.com",
		PasswordHash: &hash,
		Name:         "Password User",
		Role:         domain.RoleUser,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	users.Create(context.Background(), passwordUser)

	err := svc.RequestDeleteAccount(context.Background(), passwordUser.ID)
	if err == nil {
		t.Fatal("Expected error for password user, got nil")
	}
	if authErrCode(err) != "password_account" {
		t.Fatalf("Expected password_account, got %s", authErrCode(err))
	}
}

func TestRequestDeleteAccount_NonexistentUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	mailer := &testutil.MockMailer{}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, mailer, defaultTestConfig(), sessSvc, nil, nil)

	err := svc.RequestDeleteAccount(context.Background(), "nonexistent-id")
	if err == nil {
		t.Fatal("Expected error for nonexistent user, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("Expected user_not_found, got %s", authErrCode(err))
	}
}

func TestConfirmDeleteAccount_Success(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	mailer := &testutil.MockMailer{}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, mailer, defaultTestConfig(), sessSvc, nil, nil)

	oauthUser := &domain.User{
		ID:        "oauth-user-id",
		Email:     "oauth@example.com",
		Name:      "OAuth User",
		Role:      domain.RoleUser,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	users.Create(context.Background(), oauthUser)

	reqErr := svc.RequestDeleteAccount(context.Background(), oauthUser.ID)
	if reqErr != nil {
		t.Fatalf("RequestDeleteAccount failed: %v", reqErr)
	}

	code := testutil.GetLastVerificationCode(mailer)

	confirmErr := svc.ConfirmDeleteAccount(context.Background(), ConfirmDeleteAccountInput{
		UserID: oauthUser.ID,
		Code:   code,
	})
	if confirmErr != nil {
		t.Fatalf("ConfirmDeleteAccount failed: %v", confirmErr)
	}

	deleted, _ := users.GetByID(context.Background(), oauthUser.ID)
	if deleted != nil {
		t.Fatal("Expected user to be deleted")
	}
}

func TestConfirmDeleteAccount_InvalidCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	mailer := &testutil.MockMailer{}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, mailer, defaultTestConfig(), sessSvc, nil, nil)

	oauthUser := &domain.User{
		ID:        "oauth-user-id",
		Email:     "oauth@example.com",
		Name:      "OAuth User",
		Role:      domain.RoleUser,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	users.Create(context.Background(), oauthUser)

	err := svc.ConfirmDeleteAccount(context.Background(), ConfirmDeleteAccountInput{
		UserID: oauthUser.ID,
		Code:   "INVALID",
	})
	if err == nil {
		t.Fatal("Expected error for invalid code, got nil")
	}
	if authErrCode(err) != "delete_code_invalid" {
		t.Fatalf("Expected delete_code_invalid, got %s", authErrCode(err))
	}
}

func TestConfirmDeleteAccount_ExpiredCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	mailer := &testutil.MockMailer{}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, mailer, defaultTestConfig(), sessSvc, nil, nil)

	oauthUser := &domain.User{
		ID:        "oauth-user-id",
		Email:     "oauth@example.com",
		Name:      "OAuth User",
		Role:      domain.RoleUser,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	users.Create(context.Background(), oauthUser)

	reqErr := svc.RequestDeleteAccount(context.Background(), oauthUser.ID)
	if reqErr != nil {
		t.Fatalf("RequestDeleteAccount failed: %v", reqErr)
	}

	code := testutil.GetLastVerificationCode(mailer)

	for _, tok := range tokens.List() {
		tok.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	}

	err := svc.ConfirmDeleteAccount(context.Background(), ConfirmDeleteAccountInput{
		UserID: oauthUser.ID,
		Code:   code,
	})
	if err == nil {
		t.Fatal("Expected error for expired code, got nil")
	}
	if authErrCode(err) != "delete_code_expired" {
		t.Fatalf("Expected delete_code_expired, got %s", authErrCode(err))
	}
}

func TestConfirmDeleteAccount_CodeReuse(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	mailer := &testutil.MockMailer{}

	svc := NewAuthService(users, sessions, tokens, hasher, gen, mailer, defaultTestConfig(), sessSvc, nil, nil)

	oauthUser := &domain.User{
		ID:        "oauth-user-id",
		Email:     "oauth@example.com",
		Name:      "OAuth User",
		Role:      domain.RoleUser,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	users.Create(context.Background(), oauthUser)

	reqErr := svc.RequestDeleteAccount(context.Background(), oauthUser.ID)
	if reqErr != nil {
		t.Fatalf("RequestDeleteAccount failed: %v", reqErr)
	}

	code := testutil.GetLastVerificationCode(mailer)

	err1 := svc.ConfirmDeleteAccount(context.Background(), ConfirmDeleteAccountInput{
		UserID: oauthUser.ID,
		Code:   code,
	})
	if err1 != nil {
		t.Fatalf("First ConfirmDeleteAccount failed: %v", err1)
	}

	newUser := &domain.User{
		ID:        "new-oauth-user-id",
		Email:     "new-oauth@example.com",
		Name:      "New OAuth User",
		Role:      domain.RoleUser,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	users.Create(context.Background(), newUser)

	reqErr2 := svc.RequestDeleteAccount(context.Background(), newUser.ID)
	if reqErr2 != nil {
		t.Fatalf("RequestDeleteAccount for new user failed: %v", reqErr2)
	}

	err2 := svc.ConfirmDeleteAccount(context.Background(), ConfirmDeleteAccountInput{
		UserID: newUser.ID,
		Code:   code,
	})
	if err2 == nil {
		t.Fatal("Expected error for reused code, got nil")
	}
	if authErrCode(err2) != "delete_code_already_used" {
		t.Fatalf("Expected delete_code_already_used, got %s", authErrCode(err2))
	}
}

func newAdminLoginService(t *testing.T) *AuthService {
	t.Helper()
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	return NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil, nil)
}

func createAdminUser(t *testing.T, svc *AuthService, email, password string, banned bool) {
	t.Helper()
	hash, _ := svc.hasher.Hash(password)
	user := &domain.User{
		ID:           "admin-" + email,
		Email:        email,
		PasswordHash: &hash,
		Name:         "Admin",
		Role:         domain.RoleAdmin,
		IsVerified:   true,
		IsBanned:     banned,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := svc.users.Create(context.Background(), user); err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}
}

func TestAdminLogin_Success(t *testing.T) {
	svc := newAdminLoginService(t)
	createAdminUser(t, svc, "admin@example.com", "Passw0rd!", false)

	result, err := svc.AdminLogin(context.Background(), LoginInput{
		Email:    "admin@example.com",
		Password: "Passw0rd!",
		IP:       "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("AdminLogin failed: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.User.Role != domain.RoleAdmin {
		t.Fatalf("Expected admin role, got %s", result.User.Role)
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
	if result.Session == nil {
		t.Fatal("Expected session, got nil")
	}
}

func TestAdminLogin_DisableAdminTwoFactor_SkipsChallengeWithNoMailer(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	cfg := defaultTestConfig()
	cfg.DisableAdminTwoFactor = true
	// twoFactorSvc is real (not nil) so the test actually exercises the flag
	// rather than the already-skipped "no twoFactorSvc at all" path.
	twoFactorSvc := NewTwoFactorService(users, sessions, tokens, hasher, nil, nil, cfg, sessSvc)
	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg, sessSvc, nil, twoFactorSvc)
	createAdminUser(t, svc, "admin@example.com", "Passw0rd!", false)

	result, err := svc.AdminLogin(context.Background(), LoginInput{
		Email:    "admin@example.com",
		Password: "Passw0rd!",
		IP:       "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("AdminLogin failed with no mailer configured: %v", err)
	}
	if result.RequiresTwoFactor {
		t.Fatal("DisableAdminTwoFactor should skip the challenge, but RequiresTwoFactor was true")
	}
	if result.SessionToken == "" {
		t.Fatal("expected a session token since the challenge was skipped")
	}
}

func TestAdminLogin_NonAdmin_GenericError(t *testing.T) {
	svc := newAdminLoginService(t)
	hash, _ := svc.hasher.Hash("Passw0rd!")
	user := &domain.User{
		ID:           "user-id",
		Email:        "user@example.com",
		PasswordHash: &hash,
		Name:         "User",
		Role:         domain.RoleUser,
		IsVerified:   true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := svc.users.Create(context.Background(), user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	result, err := svc.AdminLogin(context.Background(), LoginInput{
		Email:    "user@example.com",
		Password: "Passw0rd!",
	})
	if err == nil {
		t.Fatal("Expected error for non-admin user, got nil")
	}
	if authErrCode(err) != "invalid_credentials" {
		t.Fatalf("Expected invalid_credentials, got %s", authErrCode(err))
	}
	if result != nil {
		t.Fatal("Expected nil result for non-admin user")
	}
}

func TestAdminLogin_WrongPassword(t *testing.T) {
	svc := newAdminLoginService(t)
	createAdminUser(t, svc, "admin@example.com", "Passw0rd!", false)

	_, err := svc.AdminLogin(context.Background(), LoginInput{
		Email:    "admin@example.com",
		Password: "wrongpassword",
	})
	if err == nil {
		t.Fatal("Expected error for wrong password, got nil")
	}
	if authErrCode(err) != "invalid_credentials" {
		t.Fatalf("Expected invalid_credentials, got %s", authErrCode(err))
	}
}

func TestAdminLogin_BannedAdmin(t *testing.T) {
	svc := newAdminLoginService(t)
	createAdminUser(t, svc, "admin@example.com", "Passw0rd!", true)

	_, err := svc.AdminLogin(context.Background(), LoginInput{
		Email:    "admin@example.com",
		Password: "Passw0rd!",
	})
	if err == nil {
		t.Fatal("Expected error for banned admin, got nil")
	}
	if authErrCode(err) != "user_banned" {
		t.Fatalf("Expected user_banned, got %s", authErrCode(err))
	}
}

func TestAdminLogin_NonexistentUser(t *testing.T) {
	svc := newAdminLoginService(t)

	_, err := svc.AdminLogin(context.Background(), LoginInput{
		Email:    "nobody@example.com",
		Password: "Passw0rd!",
	})
	if err == nil {
		t.Fatal("Expected error for nonexistent user, got nil")
	}
	if authErrCode(err) != "invalid_credentials" {
		t.Fatalf("Expected invalid_credentials, got %s", authErrCode(err))
	}
}

func TestAdminLogin_UnverifiedAdmin_Succeeds(t *testing.T) {
	svc := newAdminLoginService(t)
	hash, _ := svc.hasher.Hash("Passw0rd!")
	user := &domain.User{
		ID:           "admin-unverified",
		Email:        "admin-unverified@example.com",
		PasswordHash: &hash,
		Name:         "Admin",
		Role:         domain.RoleAdmin,
		IsVerified:   false,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := svc.users.Create(context.Background(), user); err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}

	cfg := defaultTestConfig()
	cfg.RequireEmailVerification = true
	svc.config = cfg

	result, err := svc.AdminLogin(context.Background(), LoginInput{
		Email:    "admin-unverified@example.com",
		Password: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("AdminLogin for unverified admin should succeed: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
}
