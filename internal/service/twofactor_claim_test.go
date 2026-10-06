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

type twoFactorBeforeLock struct {
	port.UserRepository
	before func() error
}

func (r *twoFactorBeforeLock) GetByIDForUpdate(ctx context.Context, id string) (*domain.User, error) {
	if r.before != nil {
		fn := r.before
		r.before = nil
		if err := fn(); err != nil {
			return nil, err
		}
	}
	return r.UserRepository.GetByIDForUpdate(ctx, id)
}

func TestTwoFactorVerifyReassertsCodeAndExpiryAtClaim(t *testing.T) {
	for _, name := range []string{"resend rotates code", "expires before claim"} {
		t.Run(name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			ctx := context.Background()
			cfg := defaultTestConfig()
			cfg.DisableTwoFactorChallengeBinding = true
			cfg.TwoFactorCodeTTL = 5 * time.Minute
			mail := &testutil.MockMailer{}
			users := &twoFactorBeforeLock{UserRepository: f.users}
			sessions := NewSessionService(f.db, f.sessions, &testutil.MockTokenGen{Length: 32}, DefaultSessionConfig())
			svc := NewTwoFactorService(f.db, users, f.sessions, f.tokens, f.hasher, mail, nil, cfg, sessions)
			challenge, err := svc.Challenge(ctx, f.userID)
			if err != nil {
				t.Fatal(err)
			}
			code := testutil.GetLastVerificationCode(mail)
			users.before = func() error {
				if name == "expires before claim" {
					svc.now = func() time.Time { return challenge.ExpiresAt.Add(time.Second) }
					return nil
				}
				// A committed resend between the old-code comparison and the
				// transaction's claim. Use a different code deterministically.
				replacement := "000000"
				if code == replacement {
					replacement = "111111"
				}
				ok, err := f.tokens.UpdateForResend(ctx, challenge.ID, hashOTP(replacement, cfg.OTPPepper), time.Now().Add(time.Minute), time.Now(), 3, 5)
				if err != nil {
					return err
				}
				if !ok {
					return errors.New("resend did not rotate the challenge")
				}
				return nil
			}
			if result, err := svc.Verify(ctx, api.TwoFactorVerifyInput{
				ChallengeID:  challenge.ID,
				BindingToken: "",
				Code:         code,
				IP:           "",
				UserAgent:    "",
			}); !errors.Is(err, domain.ErrTwoFactorCodeInvalid) || result != nil {
				t.Fatalf("stale verification accepted: result=%+v err=%v", result, err)
			}
			token, err := f.tokens.GetByID(ctx, challenge.ID)
			if err != nil || token == nil || token.UsedAt != nil {
				t.Fatalf("rejected claim consumed token: %+v, %v", token, err)
			}
			var count int
			if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sessions WHERE user_id = $1", f.userID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("rejected claim created a session: count=%d", count)
			}
		})
	}
}
