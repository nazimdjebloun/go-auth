package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type deliveryTestTemplates struct{ fail bool }

func (p *deliveryTestTemplates) Render(port.TemplateData) (port.TemplateResult, error) {
	if p.fail {
		return port.TemplateResult{}, errors.New("template unavailable")
	}
	return port.TemplateResult{Subject: "Code", HTML: "code", Text: "code"}, nil
}

func emailCodeRequest(t *testing.T, f *passwordTransactionFixture, kind domain.TokenType, templates port.TemplateProvider, mail port.Mailer) func(context.Context) error {
	t.Helper()
	cfg := defaultTestConfig()
	cfg.TemplateProvider = templates
	cfg.VerificationResendInterval = time.Hour
	gen := &testutil.MockTokenGen{Length: 32}
	switch kind {
	case domain.TokenVerifyEmail:
		svc := NewVerificationService(f.users, f.tokens, gen, mail, f.db, cfg)
		return func(ctx context.Context) error {
			user, err := f.users.GetByID(ctx, f.userID)
			if err != nil {
				return err
			}
			_, err = svc.SendVerification(ctx, user)
			return err
		}
	case domain.TokenDeleteAccount:
		svc := NewAuthService(f.db, f.users, f.sessions, f.tokens, f.hasher, gen, mail, cfg, nil, nil, nil)
		return func(ctx context.Context) error { return svc.RequestDeleteAccount(ctx, f.userID) }
	case domain.TokenSetPass:
		svc := NewPasswordService(f.users, f.tokens, f.hasher, gen, mail, f.sessions, f.db, cfg)
		return func(ctx context.Context) error { return svc.RequestSetPassword(ctx, f.userID) }
	default:
		t.Fatalf("unsupported delivery test type %q", kind)
		return nil
	}
}

func prepareCodeDeliveryUser(t *testing.T, f *passwordTransactionFixture) {
	t.Helper()
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET password_hash = NULL, password_pepper_version = NULL, is_verified = false WHERE id = $1", f.userID); err != nil {
		t.Fatal(err)
	}
}

func TestEmailCodeDeliveryFailureAllowsImmediateRetry(t *testing.T) {
	for _, kind := range []domain.TokenType{domain.TokenVerifyEmail, domain.TokenDeleteAccount, domain.TokenSetPass} {
		t.Run(string(kind), func(t *testing.T) {
			for _, failure := range []string{"render", "send", "canceled send"} {
				t.Run(failure, func(t *testing.T) {
					f := newPasswordTransactionFixture(t)
					prepareCodeDeliveryUser(t, f)
					templates := &deliveryTestTemplates{fail: failure == "render"}
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					failSend := failure != "render"
					mail := &testutil.MockMailer{SendFn: func(context.Context, string, string, string, string) error {
						if failSend {
							if failure == "canceled send" {
								cancel()
							}
							return errors.New("SMTP unavailable")
						}
						return nil
					}}
					request := emailCodeRequest(t, f, kind, templates, mail)
					if err := request(ctx); err == nil {
						t.Fatal("failed delivery reported success")
					}
					if token, err := f.tokens.GetLastByUserAndType(t.Context(), f.userID, kind); err != nil || token != nil {
						t.Fatalf("failed delivery left a token: %+v, %v", token, err)
					}
					templates.fail, failSend = false, false
					before := mail.SentCount()
					if err := request(t.Context()); err != nil {
						t.Fatal(err)
					}
					if mail.SentCount() != before+1 {
						t.Fatal("retry skipped delivery")
					}
				})
			}
		})
	}
}

func TestEmailCodeCleanupPreservesConcurrentToken(t *testing.T) {
	for _, kind := range []domain.TokenType{domain.TokenVerifyEmail, domain.TokenDeleteAccount, domain.TokenSetPass} {
		t.Run(string(kind), func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			prepareCodeDeliveryUser(t, f)
			otherID := uuid.NewString()
			mail := &testutil.MockMailer{SendFn: func(ctx context.Context, _, _, _, _ string) error {
				now := time.Now().UTC()
				if err := f.tokens.Create(ctx, &domain.VerificationToken{
					ID: otherID, UserID: &f.userID, Email: "user@example.com", TokenHash: otherID,
					Type: kind, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
				}); err != nil {
					return err
				}
				return errors.New("first delivery failed after a concurrent request issued its code")
			}}
			request := emailCodeRequest(t, f, kind, &deliveryTestTemplates{}, mail)
			if err := request(t.Context()); err == nil {
				t.Fatal("failed delivery reported success")
			}
			if other, err := f.tokens.GetByID(t.Context(), otherID); err != nil || other == nil || other.UsedAt != nil {
				t.Fatalf("concurrent token was invalidated: %+v, %v", other, err)
			}
			var count int
			if err := f.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM verification_tokens WHERE user_id=$1 AND type=$2", f.userID, kind).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("delivery cleanup left %d tokens, want concurrent token only", count)
			}
		})
	}
}

type cleanupFaultTokens struct {
	port.TokenRepository
	err error
}

func (r cleanupFaultTokens) DeleteUnusedByID(context.Context, string) error { return r.err }

func TestUndeliveredTokenCleanupPreservesFailure(t *testing.T) {
	want := errors.New("database unavailable during cleanup")
	if err := discardUndeliveredToken(t.Context(), cleanupFaultTokens{err: want}, "token"); !errors.Is(err, want) {
		t.Fatalf("cleanup error = %v, want %v", err, want)
	}
}
