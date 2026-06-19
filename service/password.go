package service

import (
	"context"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type PasswordService struct {
	users   port.UserRepository
	tokens  port.TokenRepository
	hasher  port.Hasher
	gen     port.TokenGenerator
	email   port.EmailSender
	config  Config
}

func NewPasswordService(
	users port.UserRepository,
	tokens port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	email port.EmailSender,
	config Config,
) *PasswordService {
	return &PasswordService{
		users:  users,
		tokens: tokens,
		hasher: hasher,
		gen:    gen,
		email:  email,
		config: config,
	}
}

func (s *PasswordService) ForgotPassword(ctx context.Context, input ForgotPasswordInput) *domain.AuthError {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	user, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil || user == nil {
		// Don't reveal whether email exists
		return nil
	}

	raw, hash, err := s.gen.Generate()
	if err != nil {
		return domain.NewError("internal_error", "Failed to generate token", 500)
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hash,
		Type:      domain.TokenResetPass,
		ExpiresAt: now.Add(s.config.TokenTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		return domain.NewError("internal_error", "Failed to store token", 500)
	}

	if s.email == nil {
		return nil
	}

	data := map[string]any{
		"Code":      raw,
		"Email":     user.Email,
		"AppName":   s.config.AppName,
		"ExpiresIn": s.config.TokenTTL.String(),
	}

	if err := s.email.Send(ctx, port.EmailData{
		To:           user.Email,
		Subject:      "Reset your password",
		TemplateName: "password_reset",
		TemplateData: data,
	}); err != nil {
		return domain.NewError("email_failed", "Failed to send reset email", 500)
	}

	return nil
}

func (s *PasswordService) ResetPassword(ctx context.Context, input ResetPasswordInput) *domain.AuthError {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	if err := validatePassword(input.NewPassword); err != nil {
		return err
	}

	tokenHash := s.gen.Hash(input.Code)
	token, err := s.tokens.GetByHash(ctx, tokenHash)
	if err != nil || token == nil {
		return domain.ErrTokenInvalid
	}

	if token.Type != domain.TokenResetPass {
		return domain.ErrTokenInvalid
	}

	if !strings.EqualFold(token.Email, input.Email) {
		return domain.ErrTokenInvalid
	}

	if token.UsedAt != nil {
		return domain.ErrTokenAlreadyUsed
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return domain.ErrTokenExpired
	}

	if token.UserID == nil {
		return domain.ErrTokenInvalid
	}

	user, err := s.users.GetByID(ctx, *token.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	hash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return domain.NewError("internal_error", "Failed to hash password", 500)
	}

	user.PasswordHash = hash
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to update password", 500)
	}

	if err := s.tokens.MarkUsed(ctx, token.ID); err != nil {
		return domain.NewError("internal_error", "Failed to mark token used", 500)
	}

	return nil
}

func (s *PasswordService) ChangePassword(ctx context.Context, input ChangePasswordInput) *domain.AuthError {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if err := s.hasher.Compare(input.OldPassword, user.PasswordHash); err != nil {
		return domain.NewError("wrong_password", "Current password is incorrect", 400)
	}

	if err := validatePassword(input.NewPassword); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return domain.NewError("internal_error", "Failed to hash password", 500)
	}

	user.PasswordHash = hash
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to update password", 500)
	}

	return nil
}
