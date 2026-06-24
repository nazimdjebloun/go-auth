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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

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
	if err.Code != "email_already_exists" {
		t.Fatalf("Expected email_already_exists, got %s", err.Code)
	}
}

func TestRegisterWeakPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg, sessSvc, nil)

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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg, sessSvc, nil)

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

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg, sessSvc, nil)

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

	_, err := svc.Login(context.Background(), LoginInput{
		Email:    "unverified@example.com",
		Password: "Passw0rd!",
	})
	if err == nil {
		t.Fatal("Expected email_not_verified error, got nil")
	}
	if err.Code != "email_not_verified" {
		t.Fatalf("Expected email_not_verified, got %s", err.Code)
	}
}

func TestLogout(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

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
