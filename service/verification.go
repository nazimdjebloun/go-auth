package service

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type VerificationService struct {
	users  port.UserRepository
	tokens port.TokenRepository
	gen    port.TokenGenerator
	email  port.EmailSender
	config Config
}

func NewVerificationService(
	users port.UserRepository,
	tokens port.TokenRepository,
	gen port.TokenGenerator,
	email port.EmailSender,
	config Config,
) *VerificationService {
	return &VerificationService{
		users:  users,
		tokens: tokens,
		gen:    gen,
		email:  email,
		config: config,
	}
}

func (s *VerificationService) VerifyEmail(ctx context.Context, code, email string) *domain.AuthError {
	tokenHash := s.gen.Hash(code)
	token, err := s.tokens.GetByHash(ctx, tokenHash)
	if err != nil || token == nil {
		return domain.ErrTokenInvalid
	}

	if token.Type != domain.TokenVerifyEmail {
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

	user.IsVerified = true
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to update user", 500)
	}

	if err := s.tokens.MarkUsed(ctx, token.ID); err != nil {
		return domain.NewError("internal_error", "Failed to mark token used", 500)
	}

	return nil
}

func (s *VerificationService) ResendVerification(ctx context.Context, userID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if user.IsVerified {
		return domain.NewError("already_verified", "Email is already verified", 400)
	}

	if s.email == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured", 500)
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
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(s.config.TokenTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		return domain.NewError("internal_error", "Failed to store token", 500)
	}

	data := map[string]any{
		"Code":      raw,
		"Email":     user.Email,
		"AppName":   s.config.AppName,
		"ExpiresIn": s.config.TokenTTL.String(),
	}

	if err := s.email.Send(ctx, port.EmailData{
		To:           user.Email,
		Subject:      "Verify your email",
		TemplateName: "verify_email",
		TemplateData: data,
	}); err != nil {
		return domain.NewError("email_failed", "Failed to send verification email", 500)
	}

	return nil
}
