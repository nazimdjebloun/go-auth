package service

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

type concurrentPasswordWinnerRepo struct {
	*testutil.MockUserRepo
	winnerHash    string
	winnerVersion *uint32
	updateCalls   int
}

type recordingForgotPasswordTokenRepo struct {
	*testutil.MockTokenRepo
	createCalls int
	deleteCalls int
}

func (r *recordingForgotPasswordTokenRepo) Create(ctx context.Context, token *domain.VerificationToken) error {
	r.createCalls++
	return r.MockTokenRepo.Create(ctx, token)
}

func (r *recordingForgotPasswordTokenRepo) DeleteUnusedByUserAndType(
	ctx context.Context,
	userID string,
	tokenType domain.TokenType,
) error {
	r.deleteCalls++
	return r.MockTokenRepo.DeleteUnusedByUserAndType(ctx, userID, tokenType)
}

type recordingForgotPasswordTxManager struct {
	calls       int
	callbackErr error
}

func (m *recordingForgotPasswordTxManager) WithTx(ctx context.Context, fn func(context.Context) error) error {
	m.calls++
	m.callbackErr = fn(ctx)
	return m.callbackErr
}

func (r *concurrentPasswordWinnerRepo) UpdatePasswordHash(
	ctx context.Context,
	userID, oldHash string,
	oldPepperVersion *uint32,
	newHash string,
	newPepperVersion *uint32,
	updatedAt time.Time,
) (bool, error) {
	r.updateCalls++
	won, err := r.MockUserRepo.UpdatePasswordHash(
		ctx,
		userID,
		oldHash,
		oldPepperVersion,
		r.winnerHash,
		r.winnerVersion,
		updatedAt,
	)
	if err != nil {
		return false, err
	}
	if !won {
		return false, errors.New("test: concurrent winner could not update password")
	}
	return r.MockUserRepo.UpdatePasswordHash(
		ctx,
		userID,
		oldHash,
		oldPepperVersion,
		newHash,
		newPepperVersion,
		updatedAt,
	)
}

func newTestPasswordService(users *testutil.MockUserRepo, tokens *testutil.MockTokenRepo, hasher *testutil.MockHasher, mailer *testutil.MockMailer) *PasswordService {
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := testutil.NewMockSessionRepo()
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	return NewPasswordService(users, tokens, hasher, gen, mailer, sessions, &testutil.MockTxManager{}, cfg)
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	err := svc.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "test@example.com"})
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
	tokens := &recordingForgotPasswordTokenRepo{MockTokenRepo: testutil.NewMockTokenRepo()}
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	txManager := &recordingForgotPasswordTxManager{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := testutil.NewMockSessionRepo()
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	svc := NewPasswordService(users, tokens, hasher, gen, mailer, sessions, txManager, cfg)

	err := svc.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "nobody@example.com"})
	if err != nil {
		t.Fatalf("should not reveal email existence, got error: %v", err)
	}
	if len(mailer.Calls) != 0 {
		t.Fatal("should not send email for nonexistent user")
	}
	if txManager.calls != 1 {
		t.Fatalf("dummy transactions = %d, want 1", txManager.calls)
	}
	if !errors.Is(txManager.callbackErr, errForgotPasswordDummyRollback) {
		t.Fatalf("dummy transaction callback error = %v, want rollback sentinel", txManager.callbackErr)
	}
	if tokens.deleteCalls != 1 || tokens.createCalls != 1 {
		t.Fatalf("dummy token operations = %d deletes/%d creates, want 1/1", tokens.deleteCalls, tokens.createCalls)
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
	svc := NewPasswordService(users, tokens, hasher, gen, nil, sessions, &testutil.MockTxManager{}, cfg)

	hash, _ := hasher.Hash("Passw0rd!")
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	// A misconfigured mailer must be visible, not indistinguishable from a
	// working one that quietly sent nothing — same reasoning as every other
	// email-sending flow in this package.
	err := svc.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "test@example.com"})
	if err == nil {
		t.Fatal("expected an error with no mailer configured, got nil")
	}
	if authErrCode(err) != "email_not_configured" {
		t.Fatalf("Code = %q, want email_not_configured", authErrCode(err))
	}
}

func TestForgotPassword_NilMailer_NonexistentUserMatchesExistingUser(t *testing.T) {
	// Configuration errors must have one response shape regardless of whether
	// the submitted email belongs to an account.
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := testutil.NewMockSessionRepo()
	svc := NewPasswordService(users, tokens, hasher, gen, nil, sessions, &testutil.MockTxManager{}, defaultTestConfig())

	err := svc.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "nobody@example.com"})
	if authErrCode(err) != "email_not_configured" {
		t.Fatalf("Code = %q, want email_not_configured", authErrCode(err))
	}
}

func TestForgotPassword_DeliveryFailureDoesNotRevealAccount(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{SendFn: func(context.Context, string, string, string, string) error {
		return errors.New("test: mail delivery unavailable")
	}}
	svc := newTestPasswordService(users, tokens, hasher, mailer)
	hash, err := hasher.Hash("OldPass1!")
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Create(context.Background(), &domain.User{
		ID: "user-1", Email: "existing@example.com", PasswordHash: &hash,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"existing@example.com", "unknown@example.com"} {
		if err := svc.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: email}); err != nil {
			t.Fatalf("ForgotPassword(%q) = %v, want generic success", email, err)
		}
	}
	if len(mailer.Calls) != 1 {
		t.Fatalf("mail attempts = %d, want one for the existing account", len(mailer.Calls))
	}
}

func TestRequestSetPassword_NoMailer_ReturnsEmailNotConfigured(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := testutil.NewMockSessionRepo()
	svc := NewPasswordService(users, tokens, hasher, gen, nil, sessions, &testutil.MockTxManager{}, defaultTestConfig())
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:        "user-1",
		Email:     "test@example.com",
		Name:      "Test",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))
	checkTestErrors(t).noError(svc.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "test@example.com"}))

	code := extractResetToken(mailer)
	if code == "" {
		t.Fatal("expected token in email")
	}

	err := svc.ResetPassword(context.Background(), api.ResetPasswordInput{
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
	if updated.PasswordPepperVersion != nil {
		t.Fatalf("unpeppered reset stored version = %v, want nil", *updated.PasswordPepperVersion)
	}
}

func TestResetPassword_NewerPepperVersionWithoutKeyFailsClosed(t *testing.T) {
	key1 := []byte("derived password pepper key version one")
	key2 := []byte("derived password pepper key version two")
	pipeline, registry, _ := newRecordingPasswordHasher(t, 1, map[uint32][]byte{1: key1})
	storedHash, err := registry.Hash(pepperPassword("OldPass1!", key2))
	if err != nil {
		t.Fatal(err)
	}
	version2 := uint32(2)
	users := testutil.NewMockUserRepo()
	user := &domain.User{
		ID:                    "user-reset-downgrade",
		Email:                 "reset-downgrade@example.com",
		PasswordHash:          &storedHash,
		PasswordPepperVersion: &version2,
		Name:                  "Reset Downgrade",
		CreatedAt:             time.Now().UTC(),
		UpdatedAt:             time.Now().UTC(),
	}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatal(err)
	}

	const code = "reset-downgrade-token"
	tokens := testutil.NewMockTokenRepo()
	token := &domain.VerificationToken{
		ID:        "reset-downgrade-token-id",
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(code),
		Type:      domain.TokenResetPass,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	}
	if err := tokens.Create(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	sessions := testutil.NewMockSessionRepo()
	if err := sessions.Create(context.Background(), &domain.Session{
		ID:        "reset-downgrade-session",
		UserID:    user.ID,
		TokenHash: "reset-downgrade-session-hash",
	}); err != nil {
		t.Fatal(err)
	}
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	svc := NewPasswordService(users, tokens, pipeline, &testutil.MockTokenGen{Length: 32}, nil, sessions, &testutil.MockTxManager{}, cfg)

	err = svc.ResetPassword(context.Background(), api.ResetPasswordInput{Code: code, NewPassword: "NewPass1!"})
	if !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("reset downgrade error = %v, want internal_error", err)
	}
	stored, err := users.GetByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PasswordHash == nil || *stored.PasswordHash != storedHash ||
		stored.PasswordPepperVersion == nil || *stored.PasswordPepperVersion != 2 {
		t.Fatalf("failed reset changed stored credential: hash=%v version=%v", stored.PasswordHash, stored.PasswordPepperVersion)
	}
	storedToken, err := tokens.GetByID(context.Background(), token.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedToken.UsedAt != nil {
		t.Fatal("failed reset consumed its token")
	}
	remaining, err := sessions.ListAllByUserID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Fatalf("failed reset revoked %d sessions, want none", 1-len(remaining))
	}
}

func TestResetPassword_InvalidCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	err := svc.ResetPassword(context.Background(), api.ResetPasswordInput{
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))
	checkTestErrors(t).noError(svc.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "test@example.com"}))
	code := extractResetToken(mailer)

	// Expire the token
	for _, tok := range tokens.List() {
		tok.ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)
	}

	err := svc.ResetPassword(context.Background(), api.ResetPasswordInput{
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))
	checkTestErrors(t).noError(svc.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "test@example.com"}))
	code := extractResetToken(mailer)

	// First reset
	err := svc.ResetPassword(context.Background(), api.ResetPasswordInput{
		Code:        code,
		NewPassword: "NewPass1!",
	})
	if err != nil {
		t.Fatalf("first reset failed: %v", err)
	}

	// Second reset with same code
	err = svc.ResetPassword(context.Background(), api.ResetPasswordInput{
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))
	checkTestErrors(t).noError(svc.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "test@example.com"}))
	code := extractResetToken(mailer)

	err := svc.ResetPassword(context.Background(), api.ResetPasswordInput{
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))
	uid := "user-1"
	checkTestErrors(t).noError(tokens.Create(context.Background(), &domain.VerificationToken{
		ID: "pending-2fa", UserID: &uid, Type: domain.TokenTwoFactor,
		ExpiresAt: time.Now().UTC().Add(time.Minute),
	}))

	err := svc.ChangePassword(context.Background(), api.ChangePasswordInput{
		UserID:      "user-1",
		OldPassword: "OldPass1!",
		NewPassword: "NewPass1!",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	challenge, err := tokens.GetByID(context.Background(), "pending-2fa")
	if err != nil || challenge != nil {
		t.Fatalf("password change left pending 2FA challenge: challenge=%+v err=%v", challenge, err)
	}
}

func TestChangePassword_ConcurrentV3WriteWinsOverV2Node(t *testing.T) {
	key2 := []byte("derived password pepper key version two")
	key3 := []byte("derived password pepper key version three")
	pipeline, registry, _ := newRecordingPasswordHasher(t, 2, map[uint32][]byte{2: key2, 3: key3})
	storedV2, err := registry.Hash(pepperPassword("OldPass1!", key2))
	if err != nil {
		t.Fatal(err)
	}
	winnerV3, err := registry.Hash(pepperPassword("ConcurrentPass1!", key3))
	if err != nil {
		t.Fatal(err)
	}
	version2, version3 := uint32(2), uint32(3)
	users := &concurrentPasswordWinnerRepo{
		MockUserRepo:  testutil.NewMockUserRepo(),
		winnerHash:    winnerV3,
		winnerVersion: &version3,
	}
	user := &domain.User{
		ID:                    "user-change-race",
		Email:                 "change-race@example.com",
		PasswordHash:          &storedV2,
		PasswordPepperVersion: &version2,
		Name:                  "Change Race",
		CreatedAt:             time.Now().UTC(),
		UpdatedAt:             time.Now().UTC(),
	}
	if err := users.Create(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	sessions := testutil.NewMockSessionRepo()
	if err := sessions.Create(context.Background(), &domain.Session{
		ID:        "change-race-session",
		UserID:    user.ID,
		TokenHash: strings.Join([]string{"change", "race", "session", "hash"}, "-"),
	}); err != nil {
		t.Fatal(err)
	}
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	svc := NewPasswordService(users, testutil.NewMockTokenRepo(), pipeline, &testutil.MockTokenGen{Length: 32}, nil, sessions, &testutil.MockTxManager{}, cfg)

	err = svc.ChangePassword(context.Background(), api.ChangePasswordInput{
		UserID:      user.ID,
		OldPassword: "OldPass1!",
		NewPassword: "RequestedPass1!",
	})
	if !errors.Is(err, domain.ErrPasswordUpdateConflict) {
		t.Fatalf("change-password race error = %v, want password_update_conflict", err)
	}
	if users.updateCalls != 1 {
		t.Fatalf("guarded password update calls = %d, want 1", users.updateCalls)
	}
	stored, err := users.GetByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PasswordHash == nil || *stored.PasswordHash != winnerV3 ||
		stored.PasswordPepperVersion == nil || *stored.PasswordPepperVersion != 3 {
		t.Fatalf("losing change overwrote v3 credential: hash=%v version=%v", stored.PasswordHash, stored.PasswordPepperVersion)
	}
	remaining, err := sessions.ListAllByUserID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 {
		t.Fatalf("losing change revoked %d sessions, want none", 1-len(remaining))
	}
}

func TestChangePassword_WrongOldPassword(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)

	hash, _ := hasher.Hash("OldPass1!")
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	err := svc.ChangePassword(context.Background(), api.ChangePasswordInput{
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	err := svc.ChangePassword(context.Background(), api.ChangePasswordInput{
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	err := svc.ChangePassword(context.Background(), api.ChangePasswordInput{
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

	err := svc.ChangePassword(context.Background(), api.ChangePasswordInput{
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
	svc := NewPasswordService(users, tokens, hasher, gen, mailer, sessions, &testutil.MockTxManager{}, cfg)

	hash, _ := hasher.Hash("OldPass1!")
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))
	checkTestErrors(t).noError(sessions.Create(context.Background(), &domain.Session{ID: "sess-1", UserID: "user-1"}))
	checkTestErrors(t).noError(sessions.Create(context.Background(), &domain.Session{ID: "sess-2", UserID: "user-1"}))

	err := svc.ChangePassword(context.Background(), api.ChangePasswordInput{
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
	svc := NewPasswordService(users, tokens, hasher, gen, mailer, sessions, &testutil.MockTxManager{}, cfg)

	hash, _ := hasher.Hash("OldPass1!")
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))
	checkTestErrors(t).noError(sessions.Create(context.Background(), &domain.Session{ID: "sess-keep", UserID: "user-1"}))
	checkTestErrors(t).noError(sessions.Create(context.Background(), &domain.Session{ID: "sess-revoke", UserID: "user-1"}))

	err := svc.ChangePassword(context.Background(), api.ChangePasswordInput{
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))
	checkTestErrors(t).noError(svc.RequestSetPassword(context.Background(), "oauth-user"))
	code := testutil.GetLastVerificationCode(mailer)
	if code == "" {
		t.Fatal("expected code in email")
	}

	err := svc.ConfirmSetPassword(context.Background(), api.ConfirmSetPasswordInput{
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	err := svc.ConfirmSetPassword(context.Background(), api.ConfirmSetPasswordInput{
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
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		PasswordHash: &hash,
		Name:         "Test",
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	err := svc.ConfirmSetPassword(context.Background(), api.ConfirmSetPasswordInput{
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

// A set-password code consumed by a concurrent request must fail this
// request with code_used — not overwrite the winner's password. The second
// confirm passes every pre-check (the user still has no password and the
// token mock still shows it unused, exactly the interleaving a real race
// produces), so only the repository's conditional claim can stop it.
func TestConfirmSetPassword_ConsumedConcurrently(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	svc := newTestPasswordService(users, tokens, hasher, mailer)
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))
	checkTestErrors(t).noError(svc.RequestSetPassword(context.Background(), "oauth-user"))
	code := testutil.GetLastVerificationCode(mailer)
	if code == "" {
		t.Fatal("expected code in email")
	}

	if err := svc.ConfirmSetPassword(context.Background(), api.ConfirmSetPasswordInput{
		UserID:      "oauth-user",
		Code:        code,
		NewPassword: "NewPass1!",
	}); err != nil {
		t.Fatalf("first confirm failed: %v", err)
	}

	// Simulate the losing side of the race: as far as every pre-check can
	// tell, the code is still live and no password is set yet.
	user, _ := users.GetByID(context.Background(), "oauth-user")
	user.PasswordHash = nil
	user.PasswordPepperVersion = nil
	checkTestErrors(t).noError(users.Update(context.Background(), user))

	err := svc.ConfirmSetPassword(context.Background(), api.ConfirmSetPasswordInput{
		UserID:      "oauth-user",
		Code:        code,
		NewPassword: "OtherPass2@",
	})
	if err == nil {
		t.Fatal("expected error for a concurrently consumed code, got nil")
	}
	if authErrCode(err) != "code_used" {
		t.Fatalf("expected code_used, got %s", authErrCode(err))
	}

	user, _ = users.GetByID(context.Background(), "oauth-user")
	if user.PasswordHash != nil {
		t.Fatal("losing confirm must not write a password")
	}
}

func TestConfirmSetPassword_StalePepperReturnsExpired(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	mailer := &testutil.MockMailer{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := testutil.NewMockSessionRepo()
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	cfg.PepperRotatedAt = time.Now().UTC()
	svc := NewPasswordService(users, tokens, hasher, gen, mailer, sessions, &testutil.MockTxManager{}, cfg)
	checkTestErrors(t).noError(users.Create(context.Background(), &domain.User{
		ID:        "oauth-user",
		Email:     "oauth@example.com",
		Name:      "OAuth",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}))

	if err := svc.RequestSetPassword(context.Background(), "oauth-user"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	code := testutil.GetLastVerificationCode(mailer)
	if code == "" {
		t.Fatal("expected code in email")
	}
	for _, tok := range tokens.List() {
		tok.CreatedAt = time.Now().UTC().Add(-time.Hour)
	}

	err := svc.ConfirmSetPassword(context.Background(), api.ConfirmSetPasswordInput{
		UserID:      "oauth-user",
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
		{"above 72 bytes (bcrypt's limit)", string(make([]byte, 129)), true},
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
	long := make([]byte, 73)
	for i := range long {
		long[i] = 'a'
	}
	long[0] = '1'
	err := p.Validate(string(long))
	if err == nil {
		t.Fatal("expected error for a 73-byte password (bcrypt's limit is 72 bytes)")
	}

	short := make([]byte, 72)
	for i := range short {
		short[i] = 'a'
	}
	short[0] = '1'
	err = p.Validate(string(short))
	if err != nil {
		t.Fatalf("72-byte password with digit should be valid: %v", err)
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
	if authErrMessage(err) != "Password must be at least 8 characters" {
		t.Fatalf("unexpected message: %s", authErrMessage(err))
	}

	err = p.Validate("12345678")
	if err == nil {
		t.Fatal("expected error for no letter")
	}
	if authErrMessage(err) != "Password must be at least 8 characters with a letter" {
		t.Fatalf("unexpected message: %s", authErrMessage(err))
	}

	err = p.Validate("abcdefgh")
	if err == nil {
		t.Fatal("expected error for no digit")
	}
	if authErrMessage(err) != "Password must be at least 8 characters with a digit" {
		t.Fatalf("unexpected message: %s", authErrMessage(err))
	}

	p2 := domain.PasswordPolicy{MinLength: 10, RequireUppercase: true, RequireSpecial: true, RequireDigit: true}
	err = p2.Validate("abcdefghij1")
	if err == nil {
		t.Fatal("expected error")
	}
	if authErrMessage(err) != "Password must be at least 10 characters with an uppercase letter, a special character" {
		t.Fatalf("unexpected message: %s", authErrMessage(err))
	}
}
