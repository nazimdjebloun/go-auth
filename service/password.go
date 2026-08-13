package service

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/port"
)

const setPasswordCodeTTL = 10 * time.Minute

type PasswordService struct {
	users     port.UserRepository
	tokens    port.TokenRepository
	hasher    port.Hasher
	gen       port.TokenGenerator
	mailer    port.Mailer
	templates port.TemplateProvider
	sessions  port.SessionRepository
	config    Config
	log       *slog.Logger
	audit     AuditPublisher
}

func NewPasswordService(
	users port.UserRepository,
	tokens port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	mailer port.Mailer,
	sessions port.SessionRepository,
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
		config:    config,
		log:       config.Logger,
		audit:     config.Audit,
	}
}

func (s *PasswordService) ForgotPassword(ctx context.Context, input ForgotPasswordInput) error {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	user, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil || user == nil {
		// Constant-time: simulate token work to prevent timing-based email enumeration
		_, _ = s.gen.Generate()
		_, _ = s.gen.Generate()
		return nil
	}

	if s.mailer == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured")
	}

	raw, err := s.gen.Generate()
	if err != nil {
		s.log.Error("failed to generate token", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	now := time.Now().UTC()

	// Invalidate any previous unused reset tokens for this user so only the
	// most recent request is valid.
	if err := s.tokens.DeleteUnusedByUserAndType(ctx, user.ID, domain.TokenResetPass); err != nil {
		s.log.Error("failed to invalidate previous tokens", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(raw),
		Type:      domain.TokenResetPass,
		ExpiresAt: now.Add(s.config.TokenTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		s.log.Error("failed to store reset token", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	if s.mailer == nil {
		return nil
	}

	url := s.config.BaseURL + "/reset-password?token=" + raw
	result, err := s.templates.Render(port.PasswordResetData{
		AppName:   s.config.AppName,
		ResetURL:  url,
		ExpiresIn: s.config.TokenTTL,
	})
	if err != nil {
		s.log.Error("failed to render reset email template", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	if err := s.mailer.Send(ctx, user.Email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send reset email", "err", err, "user_id", user.ID)
		return domain.NewError("email_failed", "Failed to send reset email")
	}

	s.log.Info("password reset requested", "user_id", user.ID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewPasswordResetRequestedEvent(user.Email, nil, ""))
	}

	return nil
}

func (s *PasswordService) ResetPassword(ctx context.Context, input ResetPasswordInput) error {
	if err := s.config.PasswordPolicy.Validate(input.NewPassword); err != nil {
		return err
	}

	token, err := s.tokens.GetByHash(ctx, hashToken(input.Code))
	if err != nil || token == nil {
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
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	hash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		s.log.Error("failed to hash password", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	user.PasswordHash = &hash
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		s.log.Error("failed to update password", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	if err := s.tokens.MarkUsed(ctx, token.ID); err != nil {
		s.log.Error("failed to mark token used", "err", err, "token_id", token.ID)
		return domain.ErrInternal
	}

	// Invalidate every session after a password reset so a stolen session
	// cookie cannot outlive credential recovery.
	if err := s.sessions.DeleteAllForUser(ctx, user.ID); err != nil {
		s.log.Error("failed to revoke sessions after password reset", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	s.log.Info("password reset completed", "user_id", user.ID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewPasswordResetCompletedEvent(user.ID, nil, ""))
	}

	return nil
}

func (s *PasswordService) RequestSetPassword(ctx context.Context, userID string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if user.HasPassword() {
		return domain.NewError("already_set", "User already has a password")
	}

	if s.mailer == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured")
	}

	raw, err := otp.Generate(8)
	if err != nil {
		s.log.Error("failed to generate OTP", "err", err, "user_id", userID)
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
		TokenHash: hashToken(raw),
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

func (s *PasswordService) ConfirmSetPassword(ctx context.Context, input ConfirmSetPasswordInput) error {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if user.HasPassword() {
		return domain.NewError("already_set", "User already has a password")
	}

	if err := s.config.PasswordPolicy.Validate(input.NewPassword); err != nil {
		return err
	}

	token, err := s.tokens.GetByHash(ctx, hashToken(input.Code))
	if err != nil || token == nil {
		return domain.NewError("invalid_code", "Invalid set password code")
	}

	if token.Type != domain.TokenSetPass {
		return domain.NewError("invalid_code", "Invalid set password code")
	}

	if token.UsedAt != nil {
		return domain.NewError("code_used", "Set password code has already been used")
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return domain.ErrResetTokenExpired
	}

	if token.UserID == nil || *token.UserID != input.UserID {
		return domain.NewError("invalid_code", "Invalid set password code")
	}

	hash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		s.log.Error("failed to hash password", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	if err := s.users.SetPasswordAndVerify(ctx, input.UserID, hash, token.ID); err != nil {
		s.log.Error("failed to set password", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("password set via code", "user_id", input.UserID)
	return nil
}

func (s *PasswordService) ChangePassword(ctx context.Context, input ChangePasswordInput) error {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if !user.HasPassword() {
		return domain.NewError("no_password", "No password set. Use set-password instead.")
	}
	if err := s.hasher.Compare(input.OldPassword, *user.PasswordHash); err != nil {
		return domain.NewError("wrong_password", "Current password is incorrect")
	}

	if err := s.config.PasswordPolicy.Validate(input.NewPassword); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		s.log.Error("failed to hash password", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	user.PasswordHash = &hash
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		s.log.Error("failed to update password", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	if input.ExceptSessionID != "" {
		if err := s.sessions.DeleteAllForUserExcept(ctx, input.UserID, input.ExceptSessionID); err != nil {
			s.log.Error("failed to revoke sessions", "err", err, "user_id", input.UserID)
			return domain.ErrInternal
		}
	} else {
		if err := s.sessions.DeleteAllForUser(ctx, input.UserID); err != nil {
			s.log.Error("failed to revoke sessions", "err", err, "user_id", input.UserID)
			return domain.ErrInternal
		}
	}

	s.log.Info("password changed", "user_id", input.UserID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewPasswordChangedEvent(input.UserID, nil, ""))
	}

	return nil
}
