package service

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func newTestPasswordService(users *testutil.MockUserRepo, tokens *testutil.MockTokenRepo, hasher *testutil.MockHasher, mailer *testutil.MockMailer) *PasswordService {
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := testutil.NewMockSessionRepo()
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	return NewPasswordService(users, tokens, hasher, gen, mailer, sessions, cfg)
}

func extractResetToken(mailer *testutil.MockMailer) string {
	if len(mailer.Calls) == 0 {
		return ""
	}
	text := mailer.Calls[len(mailer.Calls)-1].Text
	// Find a URL containing ?token= in the text
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		if tok := u.Query().Get("token"); tok != "" {
			return tok
		}
	}
	return ""
}

func TestForgotPassword_ExistingUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("Passw0rd!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "test@example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mailer.Calls) != 1 {
		t.Fatalf("expected 1 email, got %d", len(mailer.Calls))
	}
	if mailer.Calls[0].To != "test@example.com" {
		t.Fatalf("expected email to test@example.com, got %s", mailer.Calls[0].To)
	}
}

func TestForgotPassword_NonexistentUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "nobody@example.com"})
	if err != nil {
		t.Fatalf("should not reveal email existence, got error: %v", err)
	}
	if len(mailer.Calls) != 0 {
		t.Fatal("should not send email for nonexistent user")
	}
}

func TestForgotPassword_NilMailer(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := testutil.NewMockSessionRepo()
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	svc := NewPasswordService(users, tokens, hasher, gen, nil, sessions, cfg)

	hash, _ := hasher.Hash("Passw0rd!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	// A misconfigured mailer must be visible, not indistinguishable from a
	// working one that quietly sent nothing — same reasoning as every other
	// email-sending flow in this package.
	err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "test@example.com"})
	if err == nil {
		t.Fatal("expected an error with no mailer configured, got nil")
	}
	if authErrCode(err) != "email_not_configured" {
		t.Fatalf("Code = %q, want email_not_configured", authErrCode(err))
	}
}

func TestForgotPassword_NilMailer_NonexistentUserStillSilent(t *testing.T) {
	// The enumeration-resistant branch (user not found) must keep returning
	// nil regardless of mailer state — it never reaches the mailer check.
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := testutil.NewMockSessionRepo()
	svc := NewPasswordService(users, tokens, hasher, gen, nil, sessions, defaultTestConfig())

	err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "nobody@example.com"})
	if err != nil {
		t.Fatalf("should not reveal email existence even with no mailer, got error: %v", err)
	}
}

func TestRequestSetPassword_NoMailer_ReturnsEmailNotConfigured(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := testutil.NewMockSessionRepo()
	svc := NewPasswordService(users, tokens, hasher, gen, nil, sessions, defaultTestConfig())

	users.Create(context.Background(), &domain.User{
		ID:        "user-1",
		Email:     "test@example.com",
		Name:      "Test",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	err := svc.RequestSetPassword(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected an error with no mailer configured, got nil")
	}
	if authErrCode(err) != "email_not_configured" {
		t.Fatalf("Code = %q, want email_not_configured", authErrCode(err))
	}
}

func TestResetPassword_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("OldPass1!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "test@example.com"})

	code := extractResetToken(mailer)
	if code == "" {
		t.Fatal("expected token in email")
	}

	err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Code:        code,
		NewPassword: "NewPass1!",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	updated, _ := users.GetByID(context.Background(), "user-1")
	if updated == nil {
		t.Fatal("expected user to exist")
	}
}

func TestResetPassword_InvalidCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Code:        "INVALID",
		NewPassword: "NewPass1!",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "reset_token_invalid" {
		t.Fatalf("expected reset_token_invalid, got %s", authErrCode(err))
	}
}

func TestResetPassword_ExpiredCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("OldPass1!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "test@example.com"})
	code := extractResetToken(mailer)

	// Expire the token
	for _, tok := range tokens.List() {
		tok.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	}

	err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Code:        code,
		NewPassword: "NewPass1!",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "reset_token_expired" {
		t.Fatalf("expected reset_token_expired, got %s", authErrCode(err))
	}
}

func TestResetPassword_AlreadyUsedCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("OldPass1!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "test@example.com"})
	code := extractResetToken(mailer)

	// First reset
	err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Code:        code,
		NewPassword: "NewPass1!",
	})
	if err != nil {
		t.Fatalf("first reset failed: %v", err)
	}

	// Second reset with same code
	err = svc.ResetPassword(context.Background(), ResetPasswordInput{
		Code:        code,
		NewPassword: "NewPass2!",
	})
	if err == nil {
		t.Fatal("expected error for reused code")
	}
	if authErrCode(err) != "reset_token_already_used" {
		t.Fatalf("expected reset_token_already_used, got %s", authErrCode(err))
	}
}

func TestResetPassword_WeakPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("OldPass1!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "test@example.com"})
	code := extractResetToken(mailer)

	err := svc.ResetPassword(context.Background(), ResetPasswordInput{
		Code:        code,
		NewPassword: "short",
	})
	if err == nil {
		t.Fatal("expected error for weak password")
	}
}

func TestChangePassword_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("OldPass1!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:      "user-1",
		OldPassword: "OldPass1!",
		NewPassword: "NewPass1!",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestChangePassword_WrongOldPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("OldPass1!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:      "user-1",
		OldPassword: "WrongPass1!",
		NewPassword: "NewPass1!",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "wrong_password" {
		t.Fatalf("expected wrong_password, got %s", authErrCode(err))
	}
}

func TestChangePassword_NoPasswordSet(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:      "oauth-user",
		OldPassword: "",
		NewPassword: "NewPass1!",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "no_password" {
		t.Fatalf("expected no_password, got %s", authErrCode(err))
	}
}

func TestChangePassword_WeakNewPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("OldPass1!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:      "user-1",
		OldPassword: "OldPass1!",
		NewPassword: "short",
	})
	if err == nil {
		t.Fatal("expected error for weak password")
	}
}

func TestChangePassword_NonexistentUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:      "nonexistent",
		OldPassword: "OldPass1!",
		NewPassword: "NewPass1!",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
	}
}

func TestChangePassword_RevokesOtherSessions(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	svc := NewPasswordService(users, tokens, hasher, gen, mailer, sessions, cfg)

	hash, _ := hasher.Hash("OldPass1!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	sessions.Create(context.Background(), &domain.Session{ID: "sess-1", UserID: "user-1"})
	sessions.Create(context.Background(), &domain.Session{ID: "sess-2", UserID: "user-1"})

	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:      "user-1",
		OldPassword: "OldPass1!",
		NewPassword: "NewPass1!",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessList, _ := sessions.ListAllByUserID(context.Background(), "user-1")
	if len(sessList) != 0 {
		t.Fatalf("expected all sessions revoked, got %d", len(sessList))
	}
}

func TestChangePassword_KeepsExceptSession(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	svc := NewPasswordService(users, tokens, hasher, gen, mailer, sessions, cfg)

	hash, _ := hasher.Hash("OldPass1!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	sessions.Create(context.Background(), &domain.Session{ID: "sess-keep", UserID: "user-1"})
	sessions.Create(context.Background(), &domain.Session{ID: "sess-revoke", UserID: "user-1"})

	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:          "user-1",
		OldPassword:     "OldPass1!",
		NewPassword:     "NewPass1!",
		ExceptSessionID: "sess-keep",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sessList, _ := sessions.ListAllByUserID(context.Background(), "user-1")
	if len(sessList) != 1 {
		t.Fatalf("expected 1 session kept, got %d", len(sessList))
	}
	if sessList[0].ID != "sess-keep" {
		t.Fatalf("expected sess-keep to be kept, got %s", sessList[0].ID)
	}
}

func TestRequestSetPassword_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	err := svc.RequestSetPassword(context.Background(), "oauth-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mailer.Calls) != 1 {
		t.Fatalf("expected 1 email, got %d", len(mailer.Calls))
	}
}

func TestRequestSetPassword_AlreadyHasPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("Passw0rd!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	err := svc.RequestSetPassword(context.Background(), "user-1")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "already_set" {
		t.Fatalf("expected already_set, got %s", authErrCode(err))
	}
}

func TestRequestSetPassword_UserNotFound(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	err := svc.RequestSetPassword(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "user_not_found" {
		t.Fatalf("expected user_not_found, got %s", authErrCode(err))
	}
}

func TestConfirmSetPassword_HappyPath(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	svc.RequestSetPassword(context.Background(), "oauth-user")
	code := testutil.GetLastVerificationCode(mailer)
	if code == "" {
		t.Fatal("expected code in email")
	}

	err := svc.ConfirmSetPassword(context.Background(), ConfirmSetPasswordInput{
		UserID:      "oauth-user",
		Code:        code,
		NewPassword: "NewPass1!",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	user, _ := users.GetByID(context.Background(), "oauth-user")
	if user == nil {
		t.Fatal("expected user to exist")
	}
	if user.PasswordHash == nil {
		t.Fatal("expected password hash to be set")
	}
}

func TestConfirmSetPassword_InvalidCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	err := svc.ConfirmSetPassword(context.Background(), ConfirmSetPasswordInput{
		UserID:      "oauth-user",
		Code:        "INVALID",
		NewPassword: "NewPass1!",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "invalid_code" {
		t.Fatalf("expected invalid_code, got %s", authErrCode(err))
	}
}

func TestConfirmSetPassword_AlreadyHasPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("Passw0rd!")
	users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	})

	err := svc.ConfirmSetPassword(context.Background(), ConfirmSetPasswordInput{
		UserID:      "user-1",
		Code:        "any",
		NewPassword: "NewPass1!",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if authErrCode(err) != "already_set" {
		t.Fatalf("expected already_set, got %s", authErrCode(err))
	}
}

func TestPasswordPolicyDefault(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "ab1", true},
		{"exactly 8 with letter+digit", "pass1234", false},
		{"8 chars no digit", "password", true},
		{"8 chars no letter", "12345678", true},
		{"valid mixed", "abc12345", false},
		{"empty", "", true},
		{"above 128 chars", string(make([]byte, 129)), true},
	}
	p := domain.PasswordPolicy{MinLength: 8, RequireDigit: true}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.password)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPasswordPolicyMinLength(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 10, RequireDigit: true}

	err := p.Validate("abc1234567")
	if err != nil {
		t.Fatalf("10-char password with digit should be valid: %v", err)
	}

	err = p.Validate("abc123456")
	if err == nil {
		t.Fatal("9-char password should be too short")
	}

	err = p.Validate("abc1234567")
	if err != nil {
		t.Fatalf("10-char password with letter+digit should be valid: %v", err)
	}
}

func TestPasswordPolicyUppercase(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 8, RequireUppercase: true, RequireDigit: true}

	err := p.Validate("password1")
	if err == nil {
		t.Fatal("expected error for missing uppercase")
	}

	err = p.Validate("Password1")
	if err != nil {
		t.Fatalf("password with uppercase should be valid: %v", err)
	}
}

func TestPasswordPolicySpecial(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 8, RequireSpecial: true, RequireDigit: true}

	err := p.Validate("password1")
	if err == nil {
		t.Fatal("expected error for missing special char")
	}

	err = p.Validate("passw0rd!")
	if err != nil {
		t.Fatalf("password with special char should be valid: %v", err)
	}
}

func TestPasswordPolicyAllRequirements(t *testing.T) {
	p := domain.PasswordPolicy{
		MinLength:        12,
		RequireUppercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"missing uppercase and special", "abcdefgh1234", true},
		{"missing digit and special", "ABCDefghijkl", true},
		{"missing only uppercase", "abcdefg!2345", true},
		{"missing only special", "Abcdefgh1234", true},
		{"too short", "Abc1!x", true},
		{"valid", "Abcdefgh!234", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.password)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPasswordPolicyMaxLength(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 8, RequireDigit: true}
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	long[0] = '1'
	err := p.Validate(string(long))
	if err == nil {
		t.Fatal("expected error for >128 char password")
	}

	short := make([]byte, 128)
	for i := range short {
		short[i] = 'a'
	}
	short[0] = '1'
	err = p.Validate(string(short))
	if err != nil {
		t.Fatalf("128-char password with digit should be valid: %v", err)
	}
}

func TestPasswordPolicyUnicode(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 4, RequireDigit: true}
	err := p.Validate("日本語1")
	if err != nil {
		t.Fatalf("unicode letters with digit should be valid: %v", err)
	}
	err = p.Validate("日本語a")
	if err == nil {
		t.Fatal("expected error for missing digit")
	}
}

func TestPasswordPolicyErrorMessages(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 8, RequireDigit: true}

	err := p.Validate("short")
	if err == nil {
		t.Fatal("expected error")
	}
	if authErrCode(err) != "weak_password" {
		t.Fatalf("expected weak_password code, got %s", authErrCode(err))
	}
	if err.Message != "Password must be at least 8 characters" {
		t.Fatalf("unexpected message: %s", err.Message)
	}

	err = p.Validate("12345678")
	if err == nil {
		t.Fatal("expected error for no letter")
	}
	if err.Message != "Password must be at least 8 characters with a letter" {
		t.Fatalf("unexpected message: %s", err.Message)
	}

	err = p.Validate("abcdefgh")
	if err == nil {
		t.Fatal("expected error for no digit")
	}
	if err.Message != "Password must be at least 8 characters with a digit" {
		t.Fatalf("unexpected message: %s", err.Message)
	}

	p2 := domain.PasswordPolicy{MinLength: 10, RequireUppercase: true, RequireSpecial: true, RequireDigit: true}
	err = p2.Validate("abcdefghij1")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Message != "Password must be at least 10 characters with an uppercase letter, a special character" {
		t.Fatalf("unexpected message: %s", err.Message)
	}
}
