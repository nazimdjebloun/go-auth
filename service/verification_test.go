package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/service"
)

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func newVerificationConfig() service.Config {
	return service.Config{
		AppName:             "TestApp",
		VerificationCodeTTL: 15 * time.Minute,
		TokenTTL:            1 * time.Hour,
	}
}

func createVerifiedUser(users *testutil.MockUserRepo, email string) *domain.User {
	user := &domain.User{
		ID:         "user-" + email,
		Email:      email,
		Name:       "Test User",
		Role:       domain.RoleUser,
		IsVerified: true,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	users.Create(context.Background(), user)
	return user
}

func createUnverifiedUser(users *testutil.MockUserRepo, email string) *domain.User {
	user := &domain.User{
		ID:         "user-" + email,
		Email:      email,
		Name:       "Test User",
		Role:       domain.RoleUser,
		IsVerified: false,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	users.Create(context.Background(), user)
	return user
}

// ─── SendVerification ──────────────────────────────────────────────

func TestSendVerification_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	err := svc.SendVerification(context.Background(), user)
	if err != nil {
		t.Fatalf("SendVerification failed: %v", err)
	}

	if len(mailer.Calls) != 1 {
		t.Fatalf("expected 1 mailer call, got %d", len(mailer.Calls))
	}
	if mailer.Calls[0].To != "test@example.com" {
		t.Fatalf("expected mail to test@example.com, got %s", mailer.Calls[0].To)
	}
	if mailer.Calls[0].Subject != "Verify your email - TestApp" {
		t.Fatalf("unexpected subject: %s", mailer.Calls[0].Subject)
	}
}

func TestSendVerification_NilMailer(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, nil, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	err := svc.SendVerification(context.Background(), user)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "email_not_configured" {
		t.Fatalf("expected email_not_configured, got %s", err.Code)
	}
}

func TestSendVerification_MailerError(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{
		SendFn: func(_ context.Context, _, _, _, _ string) error {
			return domain.NewError("email_failed", "smtp error", 500)
		},
	}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	err := svc.SendVerification(context.Background(), user)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "email_failed" {
		t.Fatalf("expected email_failed, got %s", err.Code)
	}
}

// ─── VerifyEmail ───────────────────────────────────────────────────

func TestVerifyEmail_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	code := "ABC123"
	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        "tok-1",
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(code),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(15 * time.Minute),
	}
	tokens.Create(context.Background(), token)

	err := svc.VerifyEmail(context.Background(), code)
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}

	updated, _ := users.GetByID(context.Background(), user.ID)
	if !updated.IsVerified {
		t.Fatal("expected user to be verified")
	}
	if updated.VerifiedAt == nil {
		t.Fatal("expected VerifiedAt to be set")
	}

	stored, _ := tokens.GetByHash(context.Background(), hashToken(code))
	if stored.UsedAt == nil {
		t.Fatal("expected token to be marked used")
	}
}

func TestVerifyEmail_InvalidCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	err := svc.VerifyEmail(context.Background(), "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "code_invalid" {
		t.Fatalf("expected code_invalid, got %s", err.Code)
	}
}

func TestVerifyEmail_AlreadyUsed(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	code := "ABC123"
	now := time.Now().UTC()
	usedAt := now.Add(-1 * time.Minute)
	token := &domain.VerificationToken{
		ID:        "tok-1",
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(code),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(15 * time.Minute),
		UsedAt:    &usedAt,
	}
	tokens.Create(context.Background(), token)

	err := svc.VerifyEmail(context.Background(), code)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "code_already_used" && err.Code != "code_expired" {
		t.Fatalf("expected code_already_used or code_expired, got %s", err.Code)
	}
}

func TestVerifyEmail_Expired(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	code := "ABC123"
	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        "tok-1",
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(code),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	tokens.Create(context.Background(), token)

	err := svc.VerifyEmail(context.Background(), code)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "code_expired" {
		t.Fatalf("expected code_expired, got %s", err.Code)
	}
}

// ─── ResendVerification ────────────────────────────────────────────

func TestResendVerification_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	err := svc.ResendVerification(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("ResendVerification failed: %v", err)
	}

	if len(mailer.Calls) != 1 {
		t.Fatalf("expected 1 mailer call, got %d", len(mailer.Calls))
	}
	if mailer.Calls[0].To != "test@example.com" {
		t.Fatalf("expected mail to test@example.com, got %s", mailer.Calls[0].To)
	}
}

func TestResendVerification_UserNotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	err := svc.ResendVerification(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", err.Code)
	}
}

func TestResendVerification_AlreadyVerified(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createVerifiedUser(users, "test@example.com")

	err := svc.ResendVerification(context.Background(), user.ID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Code != "already_verified" {
		t.Fatalf("expected already_verified, got %s", err.Code)
	}
}
