package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

func newTwoFactorConfig() service.Config {
	return service.Config{
		AppName:          "TestApp",
		BaseURL:          "http://localhost:3000",
		TwoFactorCodeTTL: 5 * time.Minute,
		URLValidator:     &port.URLValidator{AllowHTTP: true},
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
	users.Create(context.Background(), user)
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
