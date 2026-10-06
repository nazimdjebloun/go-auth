package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type loginCompareBarrier struct {
	port.Hasher
	checked chan struct{}
	release chan struct{}
	once    sync.Once
}

func (h *loginCompareBarrier) Compare(password, hash string) error {
	err := h.Hasher.Compare(password, hash)
	if err == nil {
		h.once.Do(func() {
			close(h.checked)
			<-h.release
		})
	}
	return err
}

func TestLoginCredentialReplacementCannotIssueSessionOrChallenge(t *testing.T) {
	for _, tc := range []struct {
		name      string
		twoFactor bool
		reset     bool
		admin     bool
	}{
		{"login after change", false, false, false},
		{"login after reset", false, true, false},
		{"challenge after change", true, false, false},
		{"challenge after reset", true, true, false},
		{"admin login after change", false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			user, err := f.users.GetByID(ctx, f.userID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.admin {
				if _, err := f.db.ExecContext(ctx, "UPDATE users SET role = $1 WHERE id = $2", domain.RoleAdmin, user.ID); err != nil {
					t.Fatal(err)
				}
			}
			cfg := defaultTestConfig()
			cfg.RequireEmail2FA = tc.twoFactor
			cfg.DisableAdminTwoFactor = true
			cfg.DisableTwoFactorChallengeBinding = true
			cfg.TwoFactorCodeTTL = 5 * time.Minute
			mail := &testutil.MockMailer{}
			gen := &testutil.MockTokenGen{Length: 32}
			sessions := NewSessionService(f.db, f.sessions, gen, DefaultSessionConfig())
			twoFactor := NewTwoFactorService(f.db, f.users, f.sessions, f.tokens, f.hasher, mail, nil, cfg, sessions)
			barrier := &loginCompareBarrier{Hasher: f.hasher, checked: make(chan struct{}), release: make(chan struct{})}
			defer func() {
				select {
				case <-barrier.release:
				default:
					close(barrier.release)
				}
			}()
			auth := NewAuthService(f.db, f.users, f.sessions, f.tokens, barrier, gen, mail, cfg, sessions, nil, twoFactor)
			done := make(chan error, 1)
			go func() {
				input := api.LoginInput{Email: user.Email, Password: "OldPass1!"}
				var err error
				if tc.admin {
					_, err = auth.AdminLogin(ctx, input)
				} else {
					_, err = auth.Login(ctx, input)
				}
				done <- err
			}()
			select {
			case <-barrier.checked:
			case <-ctx.Done():
				t.Fatal("login did not reach password comparison")
			}
			passwords := f.passwordService(f.hasher, f.sessions)
			if tc.reset {
				err = passwords.ResetPassword(ctx, api.ResetPasswordInput{Code: f.code, NewPassword: "NewPass2!"})
			} else {
				err = passwords.ChangePassword(ctx, api.ChangePasswordInput{UserID: f.userID, OldPassword: "OldPass1!", NewPassword: "NewPass2!"})
			}
			close(barrier.release)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, domain.ErrInvalidCredentials) {
				t.Fatalf("stale password login error = %v, want invalid_credentials", err)
			}
			var count int
			if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sessions WHERE user_id = $1", f.userID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("stale password created %d sessions", count)
			}
			token, err := f.tokens.GetLastByUserAndType(ctx, f.userID, domain.TokenTwoFactor)
			if err != nil || token != nil {
				t.Fatalf("stale password created a challenge: %+v, %v", token, err)
			}
		})
	}
}

func TestTwoFactorVerifyAuditFailureRollsBackClaimAndSession(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	ctx := context.Background()
	cfg := defaultTestConfig()
	cfg.DisableTwoFactorChallengeBinding = true
	cfg.TwoFactorCodeTTL = 5 * time.Minute
	mail := &testutil.MockMailer{}
	sessions := NewSessionService(f.db, f.sessions, &testutil.MockTokenGen{Length: 32}, DefaultSessionConfig())
	svc := NewTwoFactorService(f.db, f.users, f.sessions, f.tokens, f.hasher, mail, nil, cfg, sessions)
	challenge, err := svc.Challenge(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	code := testutil.GetLastVerificationCode(mail)
	svc.audit = failingAuditPublisher{}
	if _, err := svc.Verify(ctx, api.TwoFactorVerifyInput{
		ChallengeID:  challenge.ID,
		BindingToken: "",
		Code:         code,
		IP:           "",
		UserAgent:    "",
	}); err == nil {
		t.Fatal("audit failure must reject verification")
	}
	token, err := f.tokens.GetByID(ctx, challenge.ID)
	if err != nil || token == nil || token.UsedAt != nil {
		t.Fatalf("failed verification consumed challenge: %+v, %v", token, err)
	}
	var count int
	if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM sessions WHERE user_id = $1", f.userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("failed verification left %d sessions, want original session only", count)
	}
}
