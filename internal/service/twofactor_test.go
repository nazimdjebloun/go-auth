package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func newTwoFactorConfig() service.Config {
	return service.Config{
		CommonConfig: service.CommonConfig{
			AppName: "TestApp",
			BaseURL: "http://localhost:3000",
		},
		TwoFactorCodeTTL: 5 * time.Minute,
		URLValidator:     &port.URLValidator{AllowHTTP: true},
		OTPPepper:        []byte("test-otp-pepper-32-bytes-long!!!"),
	}
}

// newTwoFactorSvc wires only what Challenge needs. Sessions and the session
// service stay nil deliberately — they are reached from Verify, not from the
// challenge path under test, so a nil here fails loudly if that ever changes.
func newTwoFactorSvc(
	users *testutil.MockUserRepo,
	tokens *testutil.MockTokenRepo,
	mailer port.Mailer,
) *service.TwoFactorService {
	return service.NewTwoFactorService(
		users, nil, tokens, &testutil.MockHasher{}, mailer, nil, newTwoFactorConfig(), nil,
	)
}

// newTwoFactorSvcWithRotation wires a service that can reach Verify's success
// path (real session service) with an explicit pepper-rotation timestamp.
// Binding is disabled so tests don't need a binding key — the stale-pepper
// branch sits behind the binding check, which these tests aren't exercising.
func newTwoFactorSvcWithRotation(
	users *testutil.MockUserRepo,
	tokens *testutil.MockTokenRepo,
	mailer *testutil.MockMailer,
	pepperRotatedAt time.Time,
) *service.TwoFactorService {
	cfg := newTwoFactorConfig()
	cfg.DisableTwoFactorChallengeBinding = true
	cfg.OTPPepper = []byte("test-otp-pepper-32-bytes-long!!!")
	cfg.PepperRotatedAt = pepperRotatedAt
	sessions := testutil.NewMockSessionRepo()
	sessSvc := service.NewSessionService(sessions, &testutil.MockTokenGen{Length: 32}, service.DefaultSessionConfig())
	return service.NewTwoFactorService(
		users, sessions, tokens, &testutil.MockHasher{}, mailer, nil, cfg, sessSvc,
	)
}

func lastTwoFactorCode(t *testing.T, mailer *testutil.MockMailer) string {
	t.Helper()
	code := testutil.GetLastVerificationCode(mailer)
	if code == "" {
		t.Fatal("expected a 2fa code in the last email")
	}
	return code
}

func wrongTwoFactorCode(actualCode string) string {
	if strings.HasPrefix(actualCode, "0") {
		return "1" + actualCode[1:]
	}
	return "0" + actualCode[1:]
}

// backdateLineage simulates a pepper rotation after issuance: every stored
// row predates rotatedAt, so the stale-pepper branch must trigger.
func backdateLineage(t *testing.T, tokens *testutil.MockTokenRepo, d time.Duration) {
	t.Helper()
	list := tokens.List()
	if len(list) == 0 {
		t.Fatal("expected at least one stored token to backdate")
	}
	for _, tok := range list {
		tok.CreatedAt = time.Now().UTC().Add(-d)
	}
}

func TestVerify_StalePepperReturnsExpiredWithoutBurningAttempts(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	mailer := &testutil.MockMailer{}
	rotatedAt := time.Now().UTC()
	svc := newTwoFactorSvcWithRotation(users, tokens, mailer, rotatedAt)

	user := newTwoFactorUser(users, "stale@example.com")
	ch, err := svc.Challenge(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}
	backdateLineage(t, tokens, time.Hour)
	code := lastTwoFactorCode(t, mailer)

	_, err = svc.Verify(context.Background(), ch.ID, "", code, "127.0.0.1", "test-agent")
	if err == nil {
		t.Fatal("expected error for rotation-stale code, got nil")
	}
	if authErrCode(err) != "two_factor_code_expired" {
		t.Fatalf("expected two_factor_code_expired, got %s", authErrCode(err))
	}

	stored, _ := tokens.GetByID(context.Background(), ch.ID)
	if stored.Attempts != 0 {
		t.Fatalf("stale-pepper failure must not burn attempt budget, attempts=%d", stored.Attempts)
	}
}

func TestVerify_StalePepperWrongCodeAlsoExpired(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	mailer := &testutil.MockMailer{}
	svc := newTwoFactorSvcWithRotation(users, tokens, mailer, time.Now().UTC())

	user := newTwoFactorUser(users, "stale-wrong@example.com")
	ch, err := svc.Challenge(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}
	backdateLineage(t, tokens, time.Hour)
	code := lastTwoFactorCode(t, mailer)

	// The old pepper is gone, so right vs wrong is unknowable — both answer
	// expired, and no guess information leaks through distinct errors.
	_, err = svc.Verify(context.Background(), ch.ID, "", wrongTwoFactorCode(code), "127.0.0.1", "test-agent")
	if err == nil {
		t.Fatal("expected error for rotation-stale lineage, got nil")
	}
	if authErrCode(err) != "two_factor_code_expired" {
		t.Fatalf("expected two_factor_code_expired, got %s", authErrCode(err))
	}
}

func TestChallenge_SkipsStaleLineage(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	mailer := &testutil.MockMailer{}
	svc := newTwoFactorSvcWithRotation(users, tokens, mailer, time.Now().UTC())

	user := newTwoFactorUser(users, "stale-reuse@example.com")
	first, err := svc.Challenge(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("first Challenge failed: %v", err)
	}
	backdateLineage(t, tokens, time.Hour)

	// A stale lineage must not be "reused" (that would mail nothing and hand
	// back a challenge Verify can only answer expired to).
	second, err := svc.Challenge(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("second Challenge failed: %v", err)
	}
	if !second.Sent {
		t.Fatal("expected a fresh mailed code after rotation, got Sent=false")
	}
	if second.ID == first.ID {
		t.Fatal("expected a new challenge id after rotation, got the stale one back")
	}
	if len(mailer.Calls) != 2 {
		t.Fatalf("expected 2 mailer calls, got %d", len(mailer.Calls))
	}
}

func TestResend_RecoversStaleLineage(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	mailer := &testutil.MockMailer{}
	svc := newTwoFactorSvcWithRotation(users, tokens, mailer, time.Now().UTC())

	user := newTwoFactorUser(users, "stale-resend@example.com")
	ch, err := svc.Challenge(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}
	backdateLineage(t, tokens, time.Hour)

	resent, err := svc.Resend(context.Background(), ch.ID, "")
	if err != nil {
		t.Fatalf("Resend failed: %v", err)
	}
	if resent.ID != ch.ID {
		t.Fatalf("expected resend to keep the challenge id, got %s", resent.ID)
	}
	newCode := lastTwoFactorCode(t, mailer)

	// The resent code is hashed under the live pepper with a refreshed
	// created_at, so it verifies — this is the "please resend" recovery path.
	result, err := svc.Verify(context.Background(), ch.ID, "", newCode, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Verify of resent code failed: %v", err)
	}
	if result == nil || result.Session == nil {
		t.Fatal("expected a session after verifying the resent code")
	}
}

func newTwoFactorUser(users *testutil.MockUserRepo, email string) *domain.User {
	hash := "irrelevant"
	user := &domain.User{
		ID:               "user-" + email,
		Email:            email,
		Name:             "Test User",
		Role:             domain.RoleUser,
		PasswordHash:     &hash,
		IsVerified:       true,
		TwoFactorEnabled: true,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}
	if err := users.Create(context.Background(), user); err != nil {
		panic(err)
	}
	return user
}

func TestChallenge_MailsACodeAndReportsSent(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	mailer := &testutil.MockMailer{}
	svc := newTwoFactorSvc(users, tokens, mailer)

	user := newTwoFactorUser(users, "test@example.com")

	result, err := svc.Challenge(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}
	if !result.Sent {
		t.Fatal("expected Sent=true on a first challenge")
	}
	if len(mailer.Calls) != 1 {
		t.Fatalf("expected 1 mailer call, got %d", len(mailer.Calls))
	}
}

func TestChallenge_ReusesLiveLineageWithoutMailing(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	mailer := &testutil.MockMailer{}
	svc := newTwoFactorSvc(users, tokens, mailer)

	user := newTwoFactorUser(users, "test@example.com")

	first, err := svc.Challenge(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("first Challenge failed: %v", err)
	}

	second, err := svc.Challenge(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("second Challenge failed: %v", err)
	}
	if second.Sent {
		t.Fatal("expected Sent=false while the first challenge is still usable")
	}
	if second.ID != first.ID {
		t.Fatalf("expected the same challenge id back, got %s vs %s", second.ID, first.ID)
	}
	if len(mailer.Calls) != 1 {
		t.Fatalf("expected no second mail, got %d calls", len(mailer.Calls))
	}
}

// The lockout this guards against: a failed send used to leave a live lineage
// behind, so Challenge's reuse branch — which returns before reaching its own
// cleanup — handed every subsequent login a challenge whose code was never
// delivered, with no way through until it expired.
func TestChallenge_FailedSendDoesNotLockOutTheNextLogin(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()

	failing := true
	mailer := &testutil.MockMailer{
		SendFn: func(_ context.Context, _, _, _, _ string) error {
			if failing {
				return domain.NewError("email_failed", "smtp auth rejected")
			}
			return nil
		},
	}
	svc := newTwoFactorSvc(users, tokens, mailer)

	user := newTwoFactorUser(users, "test@example.com")

	if _, err := svc.Challenge(context.Background(), user.ID); err == nil {
		t.Fatal("expected the first challenge to fail on the mailer")
	}

	// Mailer recovers; the user logs in again.
	failing = false
	result, err := svc.Challenge(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("second Challenge failed: %v", err)
	}
	if !result.Sent {
		t.Fatal("expected a real send after the failed one, got Sent=false — the undelivered lineage was reused")
	}
	if len(mailer.Calls) != 2 {
		t.Fatalf("expected 2 mailer calls (one failed, one real), got %d", len(mailer.Calls))
	}
}
