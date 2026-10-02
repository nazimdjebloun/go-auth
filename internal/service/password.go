package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/port"
)

const setPasswordCodeTTL = 10 * time.Minute

var errResetTokenStateChanged = errors.New("service: reset token state changed")
var errForgotPasswordDummyRollback = errors.New("service: roll back forgot-password dummy write")

// PasswordService manages password setup, reset, and changes.
type PasswordService struct {
	users     port.UserRepository
	tokens    port.TokenRepository
	hasher    port.Hasher
	gen       port.TokenGenerator
	mailer    port.Mailer
	templates port.TemplateProvider
	sessions  port.SessionRevoker // DeleteAllForUser / DeleteAllForUserExcept
	txManager port.TxManager
	config    Config
	log       *slog.Logger
	audit     AuditPublisher
	recovery  port.RecoveryEnqueuer
}

// NewPasswordService returns a password service.
func NewPasswordService(
	users port.UserRepository,
	tokens port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	mailer port.Mailer,
	sessions port.SessionRevoker,
	txManager port.TxManager,
	config Config,
) *PasswordService {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	templates := resolveTemplates(config.TemplateProvider, config.URLValidator)
	return &PasswordService{
		users:     users,
		tokens:    tokens,
		hasher:    hasher,
		gen:       gen,
		mailer:    mailer,
		templates: templates,
		sessions:  sessions,
		txManager: txManager,
		config:    config,
		log:       config.Logger,
		audit:     config.Audit,
	}
}

// ForgotPassword queues an account-independent recovery request. A missing
// queue fails closed instead of falling back to account-dependent SMTP work.
func (s *PasswordService) ForgotPassword(ctx context.Context, input api.ForgotPasswordInput) error {
	if s.mailer == nil {
		return domain.ErrEmailNotConfigured
	}
	if s.recovery == nil {
		return domain.ErrInternal
	}
	return enqueueRecovery(ctx, s.recovery, port.RecoveryPasswordReset, input.Email, s.log)
}

func (s *PasswordService) sendPasswordReset(ctx context.Context, input api.ForgotPasswordInput) error {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	if s.mailer == nil {
		// This check precedes the account lookup so a configuration failure has
		// one response shape regardless of whether the submitted email exists.
		return domain.ErrEmailNotConfigured
	}

	user, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil {
		s.log.Error("forgot-password account lookup failed", "err", err)
		s.burnForgotPasswordDummy(ctx)
		return err
	}
	if user == nil || !user.HasPassword() {
		s.burnForgotPasswordDummy(ctx)
		return nil
	}

	raw, err := s.gen.Generate()
	if err != nil {
		s.log.Error("failed to generate token", "err", err, "user_id", user.ID)
		return err
	}

	now := time.Now().UTC()

	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(raw),
		Type:      domain.TokenResetPass,
		ExpiresAt: now.Add(s.config.TokenTTL),
	}

	if err := s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		return s.writePasswordResetToken(txCtx, user.ID, token)
	}); err != nil {
		s.log.Error("failed to replace reset token", "err", err, "user_id", user.ID)
		return err
	}

	url := s.config.BaseURL + "/reset-password?token=" + raw
	result, err := s.templates.Render(port.PasswordResetData{
		AppName:   s.config.AppName,
		ResetURL:  url,
		ExpiresIn: s.config.TokenTTL,
	})
	if err != nil {
		s.log.Error("failed to render reset email template", "err", err, "user_id", user.ID)
		return err
	}

	if err := s.mailer.Send(ctx, user.Email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send reset email", "err", err, "user_id", user.ID)
		return err
	}

	s.log.Info("password reset requested", "user_id", user.ID)

	if s.audit != nil {
		if err := s.audit.Record(ctx, audit.NewPasswordResetRequestedEvent(user.Email, nil, "")); err != nil {
			s.log.Error("failed to record password reset request", "err", err, "user_id", user.ID)
		}
	}

	return nil
}

// burnForgotPasswordDummy mirrors the local work of the real reset-request
// path without sending mail or leaving attacker-triggered rows behind. The
// deliberate sentinel makes a real token INSERT and cleanup query roll back;
// infrastructure failures are logged but never change the public, enumeration-
// safe response.
func (s *PasswordService) burnForgotPasswordDummy(ctx context.Context) {
	raw, err := s.gen.Generate()
	if err != nil {
		s.log.Error("forgot-password dummy token generation failed", "err", err)
		return
	}

	now := time.Now().UTC()
	dummyUserID := generateID()
	dummyToken := &domain.VerificationToken{
		ID:        generateID(),
		Email:     "forgot-password-dummy@invalid",
		TokenHash: hashToken(raw),
		Type:      domain.TokenResetPass,
		ExpiresAt: now.Add(s.config.TokenTTL),
		CreatedAt: now,
	}
	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := s.writePasswordResetToken(txCtx, dummyUserID, dummyToken); err != nil {
			return err
		}
		return errForgotPasswordDummyRollback
	})
	if err != nil && !errors.Is(err, errForgotPasswordDummyRollback) {
		s.log.Error("forgot-password dummy database work failed", "err", err)
	}

	// Rendering is part of the real path after persistence. A render failure
	// is operationally useful, but must not change the generic response.
	if _, renderErr := s.templates.Render(port.PasswordResetData{
		AppName:   s.config.AppName,
		ResetURL:  s.config.BaseURL + "/reset-password?token=" + raw,
		ExpiresIn: s.config.TokenTTL,
	}); renderErr != nil {
		s.log.Error("forgot-password dummy template render failed", "err", renderErr)
	}
}

// writePasswordResetToken is the shared database shape for real and dummy
// forgot-password requests. Its caller supplies the transaction boundary:
// the real path commits, while the dummy path deliberately rolls back.
func (s *PasswordService) writePasswordResetToken(
	ctx context.Context,
	userID string,
	token *domain.VerificationToken,
) error {
	if err := s.tokens.DeleteUnusedByUserAndType(ctx, userID, domain.TokenResetPass); err != nil {
		return fmt.Errorf("deleting unused password reset tokens: %w", err)
	}
	if err := s.tokens.Create(ctx, token); err != nil {
		return fmt.Errorf("creating password reset token: %w", err)
	}
	return nil
}

// ResetPassword changes a password using a valid reset code.
func (s *PasswordService) ResetPassword(ctx context.Context, input api.ResetPasswordInput) error {
	if err := s.config.PasswordPolicy.Validate(input.NewPassword); err != nil {
		return err
	}

	token, err := s.tokens.GetByHash(ctx, hashToken(input.Code))
	if err != nil {
		return fmt.Errorf("reset password: lookup: %w", err)
	}
	if token == nil {
		return domain.ErrResetTokenInvalid
	}

	if token.Type != domain.TokenResetPass {
		return domain.ErrResetTokenInvalid
	}

	if token.UsedAt != nil {
		return domain.ErrResetTokenAlreadyUsed
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return domain.ErrResetTokenExpired
	}

	if token.UserID == nil {
		return domain.ErrResetTokenInvalid
	}

	user, err := s.users.GetByID(ctx, *token.UserID)
	if err != nil {
		return fmt.Errorf("reset password: lookup: %w", err)
	}
	if user == nil {
		return domain.ErrUserNotFound
	}
	if !user.HasPassword() {
		return domain.ErrResetTokenInvalid
	}

	hash, pepperVersion, err := hashPasswordAtLeast(s.hasher, input.NewPassword, user.PasswordPepperVersion)
	if err != nil {
		s.log.Error("failed to hash password", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	now := time.Now().UTC()
	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		// Reassert every security predicate while claiming the token. The
		// earlier read only classifies friendly errors; this guarded UPDATE is
		// the authority that serializes concurrent reset requests.
		consumed, err := s.tokens.ConsumeIfValid(txCtx, port.ConsumeTokenInput{
			ID:        token.ID,
			TokenHash: token.TokenHash,
			UserID:    user.ID,
			Type:      domain.TokenResetPass,
			UsedAt:    now,
		})
		if err != nil {
			return fmt.Errorf("consuming password reset token: %w", err)
		}
		if !consumed {
			return errResetTokenStateChanged
		}

		updated, err := guardedPasswordUpdate(txCtx, s.users, user, hash, pepperVersion, now)
		if err != nil {
			return err
		}
		if !updated {
			return domain.ErrPasswordUpdateConflict
		}

		// Session deletion participates in the same transaction, so a reset
		// cannot commit while a stolen pre-reset session remains valid.
		if err := s.sessions.DeleteAllForUser(txCtx, user.ID); err != nil {
			return fmt.Errorf("revoking sessions after password reset: %w", err)
		}
		if err := s.tokens.DeleteUnusedByUserAndType(txCtx, user.ID, domain.TokenTwoFactor); err != nil {
			return fmt.Errorf("revoking pending two-factor challenges after password reset: %w", err)
		}
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewPasswordResetCompletedEvent(user.ID, nil, "")); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		switch {
		case errors.Is(err, errResetTokenStateChanged):
			if !token.ExpiresAt.After(now) {
				return domain.ErrResetTokenExpired
			}
			return domain.ErrResetTokenInvalid
		case errors.Is(err, domain.ErrPasswordUpdateConflict):
			return domain.ErrPasswordUpdateConflict
		default:
			s.log.Error("failed to apply password reset transaction", "err", err, "user_id", user.ID)
			return domain.ErrInternal
		}
	}

	s.log.Info("password reset completed", "user_id", user.ID)
	return nil
}

// RequestSetPassword sends a password-setup code.
func (s *PasswordService) RequestSetPassword(ctx context.Context, userID string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("request set password: lookup: %w", err)
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	if user.HasPassword() {
		return domain.ErrPasswordAlreadySet
	}

	if s.mailer == nil {
		return domain.ErrEmailNotConfigured
	}

	raw, err := otp.Generate(8)
	if err != nil {
		s.log.Error("failed to generate OTP", "err", err, "user_id", userID)
		return domain.ErrInternal
	}

	if len(s.config.OTPPepper) == 0 {
		s.log.Error("set-password request refused: no OTP pepper derived — refusing")
		return domain.ErrInternal
	}

	now := time.Now().UTC()

	if err := s.tokens.DeleteUnusedByUserAndType(ctx, user.ID, domain.TokenSetPass); err != nil {
		s.log.Error("failed to invalidate previous tokens", "err", err, "user_id", userID)
		return domain.ErrInternal
	}

	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashOTP(raw, s.config.OTPPepper),
		Type:      domain.TokenSetPass,
		ExpiresAt: now.Add(setPasswordCodeTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		s.log.Error("failed to store set-password token", "err", err, "user_id", userID)
		return domain.ErrInternal
	}

	result, tplErr := s.templates.Render(port.SetPasswordData{
		AppName:   s.config.AppName,
		Code:      raw,
		ExpiresIn: setPasswordCodeTTL,
	})
	if tplErr != nil {
		s.log.Error("failed to render set-password email template", "err", tplErr, "user_id", userID)
		return domain.ErrInternal
	}
	if err := s.mailer.Send(ctx, user.Email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send set-password email", "err", err, "user_id", userID)
		return domain.NewError("email_failed", "Failed to send email")
	}

	return nil
}

// ConfirmSetPassword sets a password using a valid code.
func (s *PasswordService) ConfirmSetPassword(ctx context.Context, input api.ConfirmSetPasswordInput) error {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil {
		return fmt.Errorf("confirm set password: lookup: %w", err)
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	if user.HasPassword() {
		return domain.NewError("already_set", "User already has a password")
	}

	if err := s.config.PasswordPolicy.Validate(input.NewPassword); err != nil {
		return err
	}

	// The set-password code is an 8-char OTP (~40 bits): low-entropy, so it is
	// stored as HMAC-SHA256(OTPPepper, code). The request carries the user ID,
	// so the candidate is fetched by user+type and compared here in app code
	// with hmac.Equal (verifyOTP) — never a SQL `=` lookup over the MAC, never
	// bcrypt. Request clears unused codes before creating a new one, and the
	// latest row is the candidate. Concurrent requests can leave distinct
	// live codes; the guarded password write still permits only one winner.
	if len(s.config.OTPPepper) == 0 {
		s.log.Error("set-password confirm refused: no OTP pepper derived — refusing")
		return domain.ErrInternal
	}
	token, err := s.tokens.GetLastByUserAndType(ctx, input.UserID, domain.TokenSetPass)
	if err != nil {
		return fmt.Errorf("confirm set password: lookup: %w", err)
	}
	if token == nil {
		return domain.ErrInvalidSetPasswordCode
	}

	if token.Type != domain.TokenSetPass {
		return domain.ErrInvalidSetPasswordCode
	}

	if token.UsedAt != nil {
		return domain.ErrSetPasswordCodeUsed
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return domain.ErrResetTokenExpired
	}

	// A rotation-stale code predates the live pepper and can never verify.
	// Answer expired (request a new code, don't retry) without running the
	// HMAC — the old pepper is gone, so the outcome is unknowable either way.
	if stalePepper(token.CreatedAt, s.config.PepperRotatedAt) {
		return domain.ErrResetTokenExpired
	}

	if !verifyOTP(input.Code, token.TokenHash, s.config.OTPPepper) {
		return domain.ErrInvalidSetPasswordCode
	}

	if token.UserID == nil || *token.UserID != input.UserID {
		return domain.ErrInvalidSetPasswordCode
	}

	hash, pepperVersion, err := hashPassword(s.hasher, input.NewPassword)
	if err != nil {
		s.log.Error("failed to hash password", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	claimed, err := s.users.SetPasswordAndVerify(ctx, input.UserID, hash, pepperVersion, token.ID)
	if err != nil {
		s.log.Error("failed to set password", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}
	if !claimed {
		// The code was consumed or another credential write won after the
		// pre-check. The repository rolled back this attempt.
		return domain.ErrSetPasswordCodeUsed
	}

	s.log.Info("password set via code", "user_id", input.UserID)
	return nil
}

// ChangePassword changes a user's password.
func (s *PasswordService) ChangePassword(ctx context.Context, input api.ChangePasswordInput) error {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil {
		return fmt.Errorf("change password: lookup: %w", err)
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	if !user.HasPassword() {
		return domain.NewError("no_password", "No password set. Use set-password instead.")
	}
	if err := comparePassword(s.hasher, input.OldPassword, *user.PasswordHash, user.PasswordPepperVersion); err != nil {
		return domain.NewError("wrong_password", "Current password is incorrect")
	}

	if err := s.config.PasswordPolicy.Validate(input.NewPassword); err != nil {
		return err
	}

	hash, pepperVersion, err := hashPasswordAtLeast(s.hasher, input.NewPassword, user.PasswordPepperVersion)
	if err != nil {
		s.log.Error("failed to hash password", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		updated, err := guardedPasswordUpdate(txCtx, s.users, user, hash, pepperVersion, time.Now().UTC())
		if err != nil {
			return err
		}
		if !updated {
			return domain.ErrPasswordUpdateConflict
		}

		if input.ExceptSessionID != "" {
			if err := s.sessions.DeleteAllForUserExcept(txCtx, input.UserID, input.ExceptSessionID); err != nil {
				return fmt.Errorf("revoking other sessions after password change: %w", err)
			}
		} else if err := s.sessions.DeleteAllForUser(txCtx, input.UserID); err != nil {
			return fmt.Errorf("revoking sessions after password change: %w", err)
		}
		if err := s.tokens.DeleteUnusedByUserAndType(txCtx, input.UserID, domain.TokenTwoFactor); err != nil {
			return fmt.Errorf("revoking pending two-factor challenges after password change: %w", err)
		}
		// Inside the transaction: the record commits with the password
		// change it describes, so a crash cannot leave a rotated credential
		// with no audit record.
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewPasswordChangedEvent(input.UserID, nil, "")); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, domain.ErrPasswordUpdateConflict) {
			return domain.ErrPasswordUpdateConflict
		}
		s.log.Error("failed to apply password change transaction", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("password changed", "user_id", input.UserID)
	return nil
}
