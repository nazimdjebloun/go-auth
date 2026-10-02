package service

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func recoveryFixture(t *testing.T) (*passwordTransactionFixture, *PasswordService, *VerificationService, *testutil.MockMailer, *RecoveryWorker) {
	t.Helper()
	f := newPasswordTransactionFixture(t)
	mailer := &testutil.MockMailer{}
	cfg := defaultTestConfig()
	password := NewPasswordService(f.users, f.tokens, f.hasher, &testutil.MockTokenGen{Length: 32}, mailer, f.sessions, f.db, cfg)
	verify := NewVerificationService(f.users, f.tokens, nil, mailer, f.db, cfg)
	worker := NewRecoveryWorker(sqlstore.NewRecoveryRepository(f.db), password, verify, nil)
	return f, password, verify, mailer, worker
}

func TestPublicRecoveryQueuesWithoutLookupOrDelivery(t *testing.T) {
	f, password, verify, mailer, _ := recoveryFixture(t)
	ctx := context.Background()
	for _, email := range []string{"unverified@example.com", "passwordless@example.com"} {
		user, err := f.users.GetByID(ctx, f.userID)
		if err != nil {
			t.Fatal(err)
		}
		user.ID, user.Email, user.IsVerified = uuid.NewString(), email, false
		if email == "passwordless@example.com" {
			user.PasswordHash = nil
		}
		if err := f.users.Create(ctx, user); err != nil {
			t.Fatal(err)
		}
	}
	// Every account lookup would fail. Public requests must still enqueue
	// exactly the same shape, including unknown and already-verified addresses.
	password.users = &failingRecoveryUserLookup{UserRepository: f.users}
	verify.users = password.users
	for _, email := range []string{"password-transaction@example.com", "unverified@example.com", "passwordless@example.com", "missing@example.com"} {
		if err := password.ForgotPassword(ctx, api.ForgotPasswordInput{Email: email}); err != nil {
			t.Fatal(err)
		}
		result, err := verify.SendVerificationByEmail(ctx, email)
		if result != nil || !errors.Is(err, domain.ErrVerificationEmailSent) {
			t.Fatalf("public verification result=%v err=%v", result, err)
		}
	}
	if len(mailer.Calls) != 0 {
		t.Fatal("public recovery performed synchronous email delivery")
	}
	var count int
	if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM recovery_requests WHERE attempts = 0 AND claim_owner = ''").Scan(&count); err != nil || count != 8 {
		t.Fatalf("queued requests=%d err=%v, want 8", count, err)
	}
	if _, err := f.db.ExecContext(context.Background(), "DROP TABLE recovery_requests"); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"password-transaction@example.com", "missing@example.com"} {
		if !errors.Is(password.ForgotPassword(ctx, api.ForgotPasswordInput{Email: email}), domain.ErrInternal) {
			t.Fatal("queue outage must have an account-independent error")
		}
	}
}

func TestRecoveryWorkerSkipsIneligibleAccounts(t *testing.T) {
	for _, test := range []struct {
		name         string
		kind         port.RecoveryKind
		email        string
		passwordless bool
	}{
		{"unknown reset", port.RecoveryPasswordReset, "missing@example.com", false},
		{"unknown verification", port.RecoveryVerification, "missing@example.com", false},
		{"passwordless reset", port.RecoveryPasswordReset, "password-transaction@example.com", true},
		{"already verified", port.RecoveryVerification, "password-transaction@example.com", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, _, _, mailer, worker := recoveryFixture(t)
			if test.passwordless {
				if _, err := f.db.ExecContext(context.Background(), "UPDATE users SET password_hash = NULL WHERE id = $1", f.userID); err != nil {
					t.Fatal(err)
				}
			}
			var before int
			if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM verification_tokens").Scan(&before); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := sqlstore.NewRecoveryRepository(f.db).Enqueue(ctx, test.kind, test.email); err != nil {
				t.Fatal(err)
			}
			if processed, err := worker.ProcessOne(ctx); !processed || err != nil {
				t.Fatalf("processed=%v err=%v", processed, err)
			}
			var remaining, tokens int
			if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM recovery_requests").Scan(&remaining); err != nil {
				t.Fatal(err)
			}
			if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM verification_tokens").Scan(&tokens); err != nil {
				t.Fatal(err)
			}
			if remaining != 0 || tokens != before || len(mailer.Calls) != 0 {
				t.Fatalf("ineligible recovery: jobs=%d tokens=%d (before %d) emails=%d", remaining, tokens, before, len(mailer.Calls))
			}
		})
	}
}

func TestPublicRecoveryFailsClosedWithoutQueue(t *testing.T) {
	_, password, verify, mailer, _ := recoveryFixture(t)
	password.recovery, verify.recovery = nil, nil
	ctx := context.Background()
	if !errors.Is(password.ForgotPassword(ctx, api.ForgotPasswordInput{Email: "password-transaction@example.com"}), domain.ErrInternal) {
		t.Fatal("missing queue must not fall back to synchronous recovery")
	}
	if _, err := verify.SendVerificationByEmail(ctx, "password-transaction@example.com"); !errors.Is(err, domain.ErrInternal) {
		t.Fatal("missing queue must fail verification recovery closed")
	}
	if len(mailer.Calls) != 0 {
		t.Fatal("miswired recovery attempted SMTP")
	}
}

func TestRecoveryPersistsAcrossWorkerReplacementAndRetriesDelivery(t *testing.T) {
	for _, kind := range []port.RecoveryKind{port.RecoveryPasswordReset, port.RecoveryVerification} {
		t.Run(string(kind), func(t *testing.T) {
			f, password, verify, mailer, _ := recoveryFixture(t)
			ctx := context.Background()
			if _, err := f.db.ExecContext(context.Background(), "UPDATE users SET is_verified = false WHERE id = $1", f.userID); err != nil {
				t.Fatal(err)
			}
			if err := sqlstore.NewRecoveryRepository(f.db).Enqueue(ctx, kind, "password-transaction@example.com"); err != nil {
				t.Fatal(err)
			}
			// A replacement worker needs only durable address/kind, not an in-memory
			// raw token or code left by the process that accepted the request.
			worker := NewRecoveryWorker(sqlstore.NewRecoveryRepository(f.db), password, verify, nil)
			mailer.SendFn = func(context.Context, string, string, string, string) error {
				return errors.New("temporary delivery failure")
			}
			if processed, err := worker.ProcessOne(ctx); !processed || err == nil {
				t.Fatalf("failed delivery processed=%v err=%v", processed, err)
			}
			var attempts int
			if err := f.db.QueryRowContext(context.Background(), "SELECT attempts FROM recovery_requests").Scan(&attempts); err != nil || attempts != 1 {
				t.Fatalf("retry attempts=%d err=%v", attempts, err)
			}
			// Force the scheduled retry ready without a brittle wall-clock test.
			if _, err := f.db.ExecContext(context.Background(), "UPDATE recovery_requests SET available_at = 0"); err != nil {
				t.Fatal(err)
			}
			mailer.SendFn = nil
			if processed, err := worker.ProcessOne(ctx); !processed || err != nil {
				t.Fatalf("retry processed=%v err=%v", processed, err)
			}
			var count int
			if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM recovery_requests").Scan(&count); err != nil || count != 0 {
				t.Fatalf("completed requests=%d err=%v", count, err)
			}
			if len(mailer.Calls) != 2 {
				t.Fatalf("mailer calls=%d, want a failed send and successful retry", len(mailer.Calls))
			}
		})
	}
}

type cancelableRecoveryMailer struct{ entered chan struct{} }

type failingRecoveryTemplate struct{}

func (failingRecoveryTemplate) Render(port.TemplateData) (port.TemplateResult, error) {
	return port.TemplateResult{}, errors.New("temporary template failure")
}

func TestRecoveryVerificationRetriesAfterRenderFailure(t *testing.T) {
	f, _, verify, mailer, worker := recoveryFixture(t)
	if _, err := f.db.ExecContext(context.Background(), "UPDATE users SET is_verified = false WHERE id = $1", f.userID); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := verify.SendVerificationByEmail(ctx, "password-transaction@example.com"); !errors.Is(err, domain.ErrVerificationEmailSent) {
		t.Fatal(err)
	}
	templates := verify.templates
	verify.templates = failingRecoveryTemplate{}
	if processed, err := worker.ProcessOne(ctx); !processed || err == nil {
		t.Fatalf("render failure processed=%v err=%v", processed, err)
	}
	last, err := f.tokens.GetLastByUserAndType(ctx, f.userID, domain.TokenVerifyEmail)
	if err != nil || last != nil || len(mailer.Calls) != 0 {
		t.Fatalf("render failure left a token: token=%+v err=%v emails=%d", last, err, len(mailer.Calls))
	}
	verify.templates = templates
	if _, err := f.db.ExecContext(context.Background(), "UPDATE recovery_requests SET available_at = 0"); err != nil {
		t.Fatal(err)
	}
	if processed, err := worker.ProcessOne(ctx); !processed || err != nil {
		t.Fatalf("retry processed=%v err=%v", processed, err)
	}
	if len(mailer.Calls) != 1 {
		t.Fatalf("retry skipped delivery because an undelivered token was live: emails=%d", len(mailer.Calls))
	}
}

func (m cancelableRecoveryMailer) Send(ctx context.Context, _, _, _, _ string) error {
	close(m.entered)
	<-ctx.Done()
	return ctx.Err()
}

func TestRecoveryWorkerShutdownCancelsDeliveryAndLeavesDurableClaim(t *testing.T) {
	f, password, _, _, worker := recoveryFixture(t)
	mailer := cancelableRecoveryMailer{entered: make(chan struct{})}
	password.mailer = mailer
	if err := password.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "password-transaction@example.com"}); err != nil {
		t.Fatal(err)
	}
	worker.Start(context.Background())
	t.Cleanup(worker.Stop)
	select {
	case <-mailer.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not enter delivery")
	}
	// Delivery holds no SQL transaction; a second request can commit while SMTP
	// is blocked. Cancellation releases the worker without dropping its claim.
	if err := password.ForgotPassword(context.Background(), api.ForgotPasswordInput{Email: "missing@example.com"}); err != nil {
		t.Fatal(err)
	}
	worker.Stop()
	var count int
	if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM recovery_requests").Scan(&count); err != nil || count != 2 {
		t.Fatalf("durable requests after shutdown=%d err=%v", count, err)
	}
}
