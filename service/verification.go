package service

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type VerificationService struct {
	users  port.UserRepository
	tokens port.TokenRepository
	gen    port.TokenGenerator
	mailer port.Mailer
	config Config
}

func NewVerificationService(
	users port.UserRepository,
	tokens port.TokenRepository,
	gen port.TokenGenerator,
	mailer port.Mailer,
	config Config,
) *VerificationService {
	return &VerificationService{
		users:  users,
		tokens: tokens,
		gen:    gen,
		mailer: mailer,
		config: config,
	}
}

func (s *VerificationService) VerifyEmail(ctx context.Context, code, email string) *domain.AuthError {
	token, err := s.tokens.GetByHash(ctx, hashToken(code))
	if err != nil || token == nil {
		return domain.NewError("code_invalid", "Invalid verification code", 400)
	}

	if token.Type != domain.TokenVerifyEmail {
		return domain.NewError("code_invalid", "Invalid verification code", 400)
	}

	if token.UsedAt != nil {
		return domain.NewError("code_already_used", "This code has already been used", 410)
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return domain.NewError("code_expired", "Verification code has expired", 410)
	}

	if token.UserID == nil {
		return domain.NewError("code_invalid", "Invalid verification code", 400)
	}

	user, err := s.users.GetByID(ctx, *token.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	user.IsVerified = true
	now := time.Now().UTC()
	user.VerifiedAt = &now
	user.UpdatedAt = now

	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to update user", 500)
	}

	if err := s.tokens.MarkUsed(ctx, token.ID); err != nil {
		return domain.NewError("internal_error", "Failed to mark token used", 500)
	}

	return nil
}

var codeChars = []byte("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

func generateCode() string {
	b := make([]byte, 6)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(codeChars))))
		b[i] = codeChars[n.Int64()]
	}
	return string(b)
}

func (s *VerificationService) SendVerification(ctx context.Context, user *domain.User) *domain.AuthError {
	if s.mailer == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured", 500)
	}

	raw := generateCode()

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(raw),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(s.config.TokenTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		return domain.NewError("internal_error", "Failed to store token", 500)
	}

	html := "<p>Your verification code: <strong>" + raw + "</strong></p><p>Expires in 1 hour.</p>"
	text := "Your verification code: " + raw + " (expires in 1 hour)"

	if err := s.mailer.Send(ctx, user.Email, "Verify your email - "+s.config.AppName, html, text); err != nil {
		return domain.NewError("email_failed", "Failed to send verification email", 500)
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

	return s.SendVerification(ctx, user)
}
