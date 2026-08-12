package service_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// authErrCode extracts the Code of a *domain.AuthError for test assertions.
// Service methods return error, not *domain.AuthError directly, so tests
// that used to read err.Code need errors.As to get there.
func authErrCode(err error) string {
	var ae *domain.AuthError
	errors.As(err, &ae)
	if ae == nil {
		return ""
	}
	return ae.Code
}

func newVerificationConfig() service.Config {
	return service.Config{
		AppName:             "TestApp",
		VerificationCodeTTL: 15 * time.Minute,
		TokenTTL:            1 * time.Hour,
		URLValidator:        &port.URLValidator{AllowHTTP: true},
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

	result, err := svc.SendVerification(context.Background(), user)
	if err != nil {
		t.Fatalf("SendVerification failed: %v", err)
	}
	if !result.Sent {
		t.Fatal("expected Sent=true on a first send")
	}
	if result.ExpiresAt.IsZero() {
		t.Fatal("expected ExpiresAt to be set")
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

	_, err := svc.SendVerification(context.Background(), user)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "email_not_configured" {
		t.Fatalf("expected email_not_configured, got %s", authErrCode(err))
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

	_, err := svc.SendVerification(context.Background(), user)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "email_failed" {
		t.Fatalf("expected email_failed, got %s", authErrCode(err))
	}
}

// The three tests below pin the reused/throttled paths, which report
// themselves only through VerificationResult.Sent — a nil error covers a real
// send and a deliberate skip alike, so Sent is the assertion that separates
// them. Each also checks the mailer call count, so a regression that starts
// mailing on every request fails here rather than at someone's SMTP quota.

func TestSendVerification_ReusesOutstandingCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	now := time.Now().UTC()
	outstanding := now.Add(15 * time.Minute)
	tokens.Create(context.Background(), &domain.VerificationToken{
		ID:        "tok-live",
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken("LIVE123"),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: outstanding,
		CreatedAt: now,
	})

	result, err := svc.SendVerification(context.Background(), user)
	if err != nil {
		t.Fatalf("SendVerification failed: %v", err)
	}
	if result.Sent {
		t.Fatal("expected Sent=false while a usable code is outstanding")
	}
	if !result.ExpiresAt.Equal(outstanding) {
		t.Fatalf("expected the outstanding code's expiry %v, got %v", outstanding, result.ExpiresAt)
	}
	if len(mailer.Calls) != 0 {
		t.Fatalf("expected no mail for a reused code, got %d", len(mailer.Calls))
	}
}

func TestSendVerification_ThrottlesInsideResendInterval(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	cfg.VerificationResendInterval = 1 * time.Minute
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	// Spent, so not reusable — the throttle is what has to hold here.
	now := time.Now().UTC()
	usedAt := now.Add(-5 * time.Second)
	tokens.Create(context.Background(), &domain.VerificationToken{
		ID:        "tok-spent",
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken("SPENT12"),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(15 * time.Minute),
		UsedAt:    &usedAt,
		CreatedAt: now.Add(-10 * time.Second),
	})

	result, err := svc.SendVerification(context.Background(), user)
	if err != nil {
		t.Fatalf("SendVerification failed: %v", err)
	}
	if result.Sent {
		t.Fatal("expected Sent=false inside the resend interval")
	}
	if len(mailer.Calls) != 0 {
		t.Fatalf("expected no mail inside the resend interval, got %d", len(mailer.Calls))
	}
}

func TestSendVerification_MailsAgainOnceCodeIsSpentAndIntervalPassed(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	mailer := &testutil.MockMailer{}
	cfg := newVerificationConfig()
	cfg.VerificationResendInterval = 1 * time.Minute
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)

	user := createUnverifiedUser(users, "test@example.com")

	now := time.Now().UTC()
	tokens.Create(context.Background(), &domain.VerificationToken{
		ID:        "tok-expired",
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken("OLD1234"),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(-1 * time.Minute),
		CreatedAt: now.Add(-30 * time.Minute),
	})

	result, err := svc.SendVerification(context.Background(), user)
	if err != nil {
		t.Fatalf("SendVerification failed: %v", err)
	}
	if !result.Sent {
		t.Fatal("expected Sent=true once the old code expired and the interval passed")
	}
	if len(mailer.Calls) != 1 {
		t.Fatalf("expected 1 mailer call, got %d", len(mailer.Calls))
	}
}

// A failed send used to leave its token row behind, which the next call then
// mistook for an outstanding code — reporting "already sent" about a code that
// was never delivered, for the whole TTL. Sent=false is only trustworthy if a
// stored token implies a send the mailer accepted.
func TestSendVerification_FailedSendLeavesNoOutstandingCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	failing := true
	mailer := &testutil.MockMailer{
		SendFn: func(_ context.Context, _, _, _, _ string) error {
			if failing {
				return domain.NewError("email_failed", "smtp auth rejected", 500)
			}
			return nil
		},
	}

	cfg := newVerificationConfig()
	svc := service.NewVerificationService(users, tokens, gen, mailer, cfg)
	user := createUnverifiedUser(users, "test@example.com")

	if _, err := svc.SendVerification(context.Background(), user); err == nil {
		t.Fatal("expected the first send to fail")
	}

	// Mailer recovers; the user asks again.
	failing = false
	result, err := svc.SendVerification(context.Background(), user)
	if err != nil {
		t.Fatalf("second send failed: %v", err)
	}
	if !result.Sent {
		t.Fatal("expected a real send after the failed one, got Sent=false — the undelivered token was reused")
	}
	if len(mailer.Calls) != 2 {
		t.Fatalf("expected 2 mailer calls (one failed, one real), got %d", len(mailer.Calls))
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

	verifiedUser, err := svc.VerifyEmail(context.Background(), code)
	if err != nil {
		t.Fatalf("VerifyEmail failed: %v", err)
	}

	if verifiedUser == nil {
		t.Fatal("expected verified user to be returned")
	}
	if !verifiedUser.IsVerified {
		t.Fatal("expected user to be verified")
	}
	if verifiedUser.VerifiedAt == nil {
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

	_, err := svc.VerifyEmail(context.Background(), "NONEXISTENT")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "code_invalid" {
		t.Fatalf("expected code_invalid, got %s", authErrCode(err))
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

	_, err := svc.VerifyEmail(context.Background(), code)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "code_already_used" && authErrCode(err) != "code_expired" {
		t.Fatalf("expected code_already_used or code_expired, got %s", authErrCode(err))
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

	_, err := svc.VerifyEmail(context.Background(), code)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "code_expired" {
		t.Fatalf("expected code_expired, got %s", authErrCode(err))
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

	result, err := svc.ResendVerification(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("ResendVerification failed: %v", err)
	}
	if !result.Sent {
		t.Fatal("expected Sent=true on a first send")
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

	_, err := svc.ResendVerification(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
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

	_, err := svc.ResendVerification(context.Background(), user.ID)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "already_verified" {
		t.Fatalf("expected already_verified, got %s", authErrCode(err))
	}
}
