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

func TestPasswordChangeRevokesOutstandingResetTokens(t *testing.T) {
	for _, keep := range []bool{false, true} {
		name := "all sessions"
		if keep {
			name = "keep current session"
		}
		t.Run(name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			svc := f.passwordService(f.hasher, f.sessions)
			input := api.ChangePasswordInput{UserID: f.userID, OldPassword: "OldPass1!", NewPassword: "OwnerNew2!"}
			if keep {
				session, err := f.sessions.GetByTokenHash(t.Context(), f.session)
				if err != nil {
					t.Fatal(err)
				}
				input.ExceptSessionID = session.ID
			}
			if err := svc.ChangePassword(t.Context(), input); err != nil {
				t.Fatal(err)
			}
			if err := svc.ResetPassword(t.Context(), api.ResetPasswordInput{Code: f.code, NewPassword: "StaleLink3!"}); !errors.Is(err, domain.ErrResetTokenInvalid) {
				t.Fatalf("pre-change reset credential accepted: %v", err)
			}
			user, err := f.users.GetByID(t.Context(), f.userID)
			if err != nil || f.hasher.Compare(input.NewPassword, *user.PasswordHash) != nil {
				t.Fatalf("owner's password changed: %v", err)
			}
		})
	}
}

type resetRevocationFailure struct{ port.TokenRepository }

func (r resetRevocationFailure) DeleteUnusedByUserAndType(ctx context.Context, userID string, kind domain.TokenType) error {
	if kind == domain.TokenResetPass {
		return errInjectedRecoveryTokenWrite
	}
	return r.TokenRepository.DeleteUnusedByUserAndType(ctx, userID, kind)
}

func TestPasswordChangeResetRevocationFailureRollsBack(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	svc := f.passwordService(f.hasher, f.sessions)
	svc.tokens = resetRevocationFailure{TokenRepository: f.tokens}
	if err := svc.ChangePassword(t.Context(), api.ChangePasswordInput{UserID: f.userID, OldPassword: "OldPass1!", NewPassword: "OwnerNew2!"}); !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("revocation failure=%v, want internal_error", err)
	}
	user, err := f.users.GetByID(t.Context(), f.userID)
	if err != nil || *user.PasswordHash != f.oldHash {
		t.Fatalf("failed revocation changed credential: %v", err)
	}
	session, err := f.sessions.GetByTokenHash(t.Context(), f.session)
	if err != nil || session == nil {
		t.Fatalf("failed revocation removed session: %v", err)
	}
	if err := f.passwordService(f.hasher, f.sessions).ResetPassword(t.Context(), api.ResetPasswordInput{Code: f.code, NewPassword: "RecoveryNew3!"}); err != nil {
		t.Fatalf("rolled-back change invalidated reset token: %v", err)
	}
}

type resetIssuanceHook struct{ before func() }

func (g resetIssuanceHook) Generate() (string, error) {
	g.before()
	return "new-reset-credential", nil
}

func TestResetIssuanceCannotRestorePreChangeAuthorization(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	mail := &testutil.MockMailer{}
	svc := f.passwordService(f.hasher, f.sessions)
	svc.mailer = mail
	svc.gen = resetIssuanceHook{before: func() {
		if err := f.passwordService(f.hasher, f.sessions).ChangePassword(t.Context(), api.ChangePasswordInput{UserID: f.userID, OldPassword: "OldPass1!", NewPassword: "OwnerNew2!"}); err != nil {
			t.Fatal(err)
		}
	}}
	if err := svc.sendPasswordReset(t.Context(), api.ForgotPasswordInput{Email: "password-transaction@example.com"}); err != nil {
		t.Fatal(err)
	}
	if mail.SentCount() != 0 {
		t.Fatal("stale reset issuance sent a new link")
	}
	token, err := f.tokens.GetLastByUserAndType(t.Context(), f.userID, domain.TokenResetPass)
	if err != nil || token != nil {
		t.Fatalf("stale issuance recreated a reset credential: %+v, %v", token, err)
	}
}

func TestPasswordResetRevokesOtherOutstandingResetTokens(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	other := &domain.VerificationToken{ID: "00000000-0000-4000-8000-000000000204", UserID: &f.userID, Email: "password-transaction@example.com", TokenHash: hashToken("other-reset"), Type: domain.TokenResetPass, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := f.tokens.Create(t.Context(), other); err != nil {
		t.Fatal(err)
	}
	svc := f.passwordService(f.hasher, f.sessions)
	if err := svc.ResetPassword(t.Context(), api.ResetPasswordInput{Code: f.code, NewPassword: "RecoveryNew2!"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.ResetPassword(t.Context(), api.ResetPasswordInput{Code: "other-reset", NewPassword: "StaleLink3!"}); !errors.Is(err, domain.ErrResetTokenInvalid) {
		t.Fatalf("second reset credential survived replacement: %v", err)
	}
}
