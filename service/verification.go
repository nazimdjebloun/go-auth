package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func formatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := int(d.Hours())

	if h > 0 && d%time.Hour == 0 {
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}

	m := int(d.Minutes())
	if m == 1 {
		return "1 minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

type VerificationService struct {
	users  port.UserRepository
	tokens port.TokenRepository
	gen    port.TokenGenerator
	mailer port.Mailer
	config Config
	log    *slog.Logger
}

func NewVerificationService(
	users port.UserRepository,
	tokens port.TokenRepository,
	gen port.TokenGenerator,
	mailer port.Mailer,
	config Config,
) *VerificationService {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &VerificationService{
		users:  users,
		tokens: tokens,
		gen:    gen,
		mailer: mailer,
		config: config,
		log:    logger,
	}
}

func (s *VerificationService) VerifyEmail(ctx context.Context, code string) (*domain.User, *domain.AuthError) {
	token, err := s.tokens.GetByHash(ctx, hashToken(code))
	if err != nil || token == nil {
		return nil, domain.NewError("code_invalid", "Invalid verification code", 400)
	}

	if token.Type != domain.TokenVerifyEmail {
		return nil, domain.NewError("code_invalid", "Invalid verification code", 400)
	}

	if token.UsedAt != nil {
		return nil, domain.NewError("code_already_used", "This code has already been used", 410)
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, domain.NewError("code_expired", "Verification code has expired", 410)
	}

	if token.UserID == nil {
		return nil, domain.NewError("code_invalid", "Invalid verification code", 400)
	}

	user, err := s.users.GetByID(ctx, *token.UserID)
	if err != nil || user == nil {
		return nil, domain.ErrUserNotFound
	}

	user.IsVerified = true
	now := time.Now().UTC()
	user.VerifiedAt = &now
	user.UpdatedAt = now

	if err := s.users.Update(ctx, user); err != nil {
		s.log.Error("failed to update user", "err", err, "user_id", user.ID)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	if err := s.tokens.MarkUsed(ctx, token.ID); err != nil {
		s.log.Error("failed to mark token used", "err", err, "token_id", token.ID)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("email verified", "user_id", user.ID, "email", user.Email)
	return user, nil
}

// codeChars omits ambiguous glyphs (I/O/0/1). 8 chars from a 32-symbol
// alphabet ≈ 40 bits of entropy — enough for short-lived emailed OTPs
// when paired with rate limits.
var codeChars = []byte("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

const otpCodeLength = 8

func generateCode() string {
	b := make([]byte, otpCodeLength)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(codeChars))))
		if err != nil {
			panic("generateCode: " + err.Error())
		}
		b[i] = codeChars[n.Int64()]
	}
	return string(b)
}

func (s *VerificationService) SendVerification(ctx context.Context, user *domain.User) *domain.AuthError {
	if s.mailer == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured", 500)
	}

	if user.ID != "" {
		hasValid, err := s.tokens.HasValidByUserAndType(ctx, user.ID, domain.TokenVerifyEmail)
		if err == nil && hasValid {
			return nil
		}
	}

	raw := generateCode()

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(raw),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(s.config.VerificationCodeTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		s.log.Error("failed to store verification token", "err", err, "user_id", user.ID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	ttl := formatDuration(s.config.VerificationCodeTTL)
	html := "<p>Your verification code: <strong>" + raw + "</strong></p><p>Expires in " + ttl + ".</p>"
	text := "Your verification code: " + raw + " (expires in " + ttl + ")"

	if err := s.mailer.Send(ctx, user.Email, "Verify your email - "+s.config.AppName, html, text); err != nil {
		s.log.Error("failed to send verification email", "err", err, "user_id", user.ID)
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

func (s *VerificationService) SendVerificationByEmail(ctx context.Context, email string) *domain.AuthError {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return domain.NewError("email_not_found", "If an account exists, a verification email has been sent", 200)
	}

	if user.IsVerified {
		return domain.NewError("email_not_found", "If an account exists, a verification email has been sent", 200)
	}

	return s.SendVerification(ctx, user)
}
