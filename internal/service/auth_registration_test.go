package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type registrationDeliveryTokens struct {
	port.TokenRepository
	failure string
}

func (r registrationDeliveryTokens) GetLastByUserAndType(ctx context.Context, id string, kind domain.TokenType) (*domain.VerificationToken, error) {
	if r.failure == "lookup" {
		return nil, errors.New("verification lookup unavailable")
	}
	return r.TokenRepository.GetLastByUserAndType(ctx, id, kind)
}

func (r registrationDeliveryTokens) Create(ctx context.Context, token *domain.VerificationToken) error {
	if r.failure == "token write" {
		return errors.New("verification token write unavailable")
	}
	return r.TokenRepository.Create(ctx, token)
}

func (r registrationDeliveryTokens) DeleteUnusedByID(ctx context.Context, id string) error {
	if r.failure == "cleanup" {
		return errors.New("verification cleanup unavailable")
	}
	return r.TokenRepository.DeleteUnusedByID(ctx, id)
}

func TestRegisterVerificationDeliveryPreservesCreatedAccount(t *testing.T) {
	for _, failure := range []string{"none", "send", "render", "canceled send", "lookup", "token write", "cleanup"} {
		t.Run(failure, func(t *testing.T) {
			users := testutil.NewMockUserRepo()
			tokens := testutil.NewMockTokenRepo()
			sessions := testutil.NewMockSessionRepo()
			tx := &testutil.MockTxManager{}
			gen := &testutil.MockTokenGen{Length: 32}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			mailer := &testutil.MockMailer{SendFn: func(context.Context, string, string, string, string) error {
				if failure == "canceled send" {
					cancel()
					return context.Canceled
				}
				if failure == "send" || failure == "cleanup" {
					return errors.New("mailer unavailable")
				}
				return nil
			}}
			cfg := defaultTestConfig()
			cfg.RequireEmailVerification = true
			if failure == "render" {
				cfg.TemplateProvider = &deliveryTestTemplates{fail: true}
			}
			verify := NewVerificationService(users, registrationDeliveryTokens{TokenRepository: tokens, failure: failure}, gen, mailer, tx, cfg)
			svc := NewAuthService(tx, users, sessions, tokens, &testutil.MockHasher{}, gen, mailer, cfg, newTestSessionService(sessions, gen), verify, nil)
			input := api.RegisterInput{Email: "signup@example.test", Password: "Passw0rd!", Name: "Signup"}
			result, err := svc.Register(ctx, input)
			if err != nil || result == nil {
				t.Fatalf("committed signup reported failure: result=%v err=%v", result, err)
			}
			want := api.VerificationDeliveryFailed
			if failure == "none" {
				want = api.VerificationDeliverySent
			}
			if !result.RequiresVerification || result.VerificationDelivery != want {
				t.Fatalf("requires verification=%v, delivery=%q, want %q", result.RequiresVerification, result.VerificationDelivery, want)
			}
			if result.Session != nil || result.SessionToken != "" || result.RefreshToken != "" || result.User.IsVerified {
				t.Fatal("pending verification granted access")
			}
			user, err := users.GetByEmail(t.Context(), input.Email)
			if err != nil || user == nil || user.ID != result.User.ID {
				t.Fatalf("created account missing: %v", err)
			}
			active, err := sessions.ListAllByUserID(t.Context(), user.ID)
			if err != nil || len(active) != 0 {
				t.Fatalf("pending signup sessions=%d err=%v", len(active), err)
			}
			last, err := tokens.GetLastByUserAndType(t.Context(), user.ID, domain.TokenVerifyEmail)
			if err != nil {
				t.Fatal(err)
			}
			if failure != "none" && failure != "cleanup" && last != nil {
				t.Fatal("failed delivery left an outstanding code")
			}
			if duplicate, err := svc.Register(t.Context(), input); duplicate != nil || !errors.Is(err, domain.ErrEmailAlreadyExists) {
				t.Fatalf("duplicate signup result=%v err=%v", duplicate, err)
			}
			login, err := svc.Login(t.Context(), api.LoginInput{Email: input.Email, Password: input.Password})
			if err != nil || login == nil || !login.RequiresVerification || login.Session != nil {
				t.Fatalf("pending account cannot resume verification: result=%v err=%v", login, err)
			}
		})
	}
}

type registrationRollbackTx struct{}

func (registrationRollbackTx) WithTx(ctx context.Context, fn func(context.Context) error) error {
	return (&testutil.MockTxManager{}).WithTx(ctx, func(txCtx context.Context) error {
		if err := fn(txCtx); err != nil {
			return err
		}
		return errors.New("registration transaction rejected")
	})
}

func TestRegisterUncommittedAccountStillFails(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	sessions := testutil.NewMockSessionRepo()
	mailer := &testutil.MockMailer{}
	gen := &testutil.MockTokenGen{Length: 32}
	cfg := defaultTestConfig()
	cfg.RequireEmailVerification = true
	tx := registrationRollbackTx{}
	verify := NewVerificationService(users, tokens, gen, mailer, tx, cfg)
	svc := NewAuthService(tx, users, sessions, tokens, &testutil.MockHasher{}, gen, mailer, cfg, nil, verify, nil)
	result, err := svc.Register(t.Context(), api.RegisterInput{Email: "rollback@example.test", Password: "Passw0rd!", Name: "Rollback"})
	if result != nil || err == nil {
		t.Fatalf("failed account creation reported success: result=%v err=%v", result, err)
	}
	user, err := users.GetByEmail(t.Context(), "rollback@example.test")
	if err != nil || user != nil || mailer.SentCount() != 0 {
		t.Fatalf("rollback left an account or sent email: account present=%v sends=%d err=%v", user != nil, mailer.SentCount(), err)
	}
}

func TestPendingVerificationDeliveryDistinguishesSkippedSend(t *testing.T) {
	for _, kind := range []string{"live code", "cooldown"} {
		t.Run(kind, func(t *testing.T) {
			users := testutil.NewMockUserRepo()
			tokens := testutil.NewMockTokenRepo()
			mailer := &testutil.MockMailer{}
			cfg := defaultTestConfig()
			cfg.VerificationResendInterval = time.Hour
			verify := NewVerificationService(users, tokens, nil, mailer, &testutil.MockTxManager{}, cfg)
			id := "pending-user"
			now := time.Now().UTC()
			code := &domain.VerificationToken{
				ID: "existing-code", UserID: &id, Type: domain.TokenVerifyEmail,
				TokenHash: hashOTP("ABCD2345", cfg.OTPPepper), CreatedAt: now,
				ExpiresAt: now.Add(time.Minute),
			}
			if kind == "cooldown" {
				code.UsedAt = &now
			}
			if err := tokens.Create(t.Context(), code); err != nil {
				t.Fatal(err)
			}
			if got := verify.pendingDelivery(t.Context(), &domain.User{ID: id}); got != api.VerificationDeliveryNotSent {
				t.Fatalf("skipped attempt=%q", got)
			}
			if mailer.SentCount() != 0 {
				t.Fatal("skip sent another message")
			}
		})
	}
}
