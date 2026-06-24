package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type PasswordService struct {
	users    port.UserRepository
	tokens   port.TokenRepository
	hasher   port.Hasher
	gen      port.TokenGenerator
	mailer   port.Mailer
	sessions port.SessionRepository
	config   Config
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
	return &PasswordService{
		users:    users,
		tokens:   tokens,
		hasher:   hasher,
		gen:      gen,
		mailer:   mailer,
		sessions: sessions,
		config:   config,
	}
}

func (s *PasswordService) ForgotPassword(ctx context.Context, input ForgotPasswordInput) *domain.AuthError {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	user, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil || user == nil {
		// Don't reveal whether email exists
		return nil
	}

	raw, err := s.gen.Generate()
	if err != nil {
		return domain.NewError("internal_error", "Failed to generate token", 500)
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

	if err := s.tokens.Create(ctx, token); err != nil {
		return domain.NewError("internal_error", "Failed to store token", 500)
	}

	if s.mailer == nil {
		return nil
	}

	url := s.config.BaseURL + "/reset-password?token=" + raw
	html := "<p>Click <a href=\"" + url + "\">here</a> to reset your password. Expires in 1 hour.</p>"
	text := "Reset your password: " + url + " (expires in 1 hour)"

	if err := s.mailer.Send(ctx, user.Email, "Reset your password - "+s.config.AppName, html, text); err != nil {
		return domain.NewError("email_failed", "Failed to send reset email", 500)
	}

	return nil
}

func (s *PasswordService) ResetPassword(ctx context.Context, input ResetPasswordInput) *domain.AuthError {
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
		return domain.NewError("internal_error", "Failed to hash password", 500)
	}

	user.PasswordHash = &hash
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to update password", 500)
	}

	if err := s.tokens.MarkUsed(ctx, token.ID); err != nil {
		return domain.NewError("internal_error", "Failed to mark token used", 500)
	}

	return nil
}

func (s *PasswordService) generateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08d", n.Int64()), nil
}

func (s *PasswordService) RequestSetPassword(ctx context.Context, userID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if user.HasPassword() {
		return domain.NewError("already_set", "User already has a password", 400)
	}

	raw, err := s.generateOTP()
	if err != nil {
		return domain.NewError("internal_error", "Failed to generate OTP", 500)
	}

	now := time.Now().UTC()

	if err := s.tokens.DeleteUnusedByUserAndType(ctx, user.ID, domain.TokenSetPass); err != nil {
		return domain.NewError("internal_error", "Failed to invalidate previous tokens", 500)
	}

	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(raw),
		Type:      domain.TokenSetPass,
		ExpiresAt: now.Add(10 * time.Minute),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		return domain.NewError("internal_error", "Failed to store token", 500)
	}

	if s.mailer != nil {
		html := "<p>Your set password code: <strong>" + raw + "</strong></p><p>Expires in 10 minutes.</p>"
		text := "Your set password code: " + raw + " (expires in 10 minutes)"
		if err := s.mailer.Send(ctx, user.Email, "Set your password - "+s.config.AppName, html, text); err != nil {
			return domain.NewError("email_failed", "Failed to send email", 500)
		}
	}

	return nil
}

func (s *PasswordService) ConfirmSetPassword(ctx context.Context, input ConfirmSetPasswordInput) *domain.AuthError {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if user.HasPassword() {
		return domain.NewError("already_set", "User already has a password", 400)
	}

	if err := s.config.PasswordPolicy.Validate(input.NewPassword); err != nil {
		return err
	}

	token, err := s.tokens.GetByHash(ctx, hashToken(input.Code))
	if err != nil || token == nil {
		return domain.NewError("invalid_code", "Invalid set password code", 400)
	}

	if token.Type != domain.TokenSetPass {
		return domain.NewError("invalid_code", "Invalid set password code", 400)
	}

	if token.UsedAt != nil {
		return domain.NewError("code_used", "Set password code has already been used", 400)
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return domain.ErrResetTokenExpired
	}

	if token.UserID == nil || *token.UserID != input.UserID {
		return domain.NewError("invalid_code", "Invalid set password code", 400)
	}

	hash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return domain.NewError("internal_error", "Failed to hash password", 500)
	}

	if err := s.users.SetPasswordAndVerify(ctx, input.UserID, hash, token.ID); err != nil {
		return domain.NewError("internal_error", "Failed to set password", 500)
	}

	return nil
}

func (s *PasswordService) ChangePassword(ctx context.Context, input ChangePasswordInput) *domain.AuthError {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if !user.HasPassword() {
		return domain.NewError("no_password", "No password set. Use set-password instead.", 400)
	}
	if err := s.hasher.Compare(input.OldPassword, *user.PasswordHash); err != nil {
		return domain.NewError("wrong_password", "Current password is incorrect", 400)
	}

	if err := s.config.PasswordPolicy.Validate(input.NewPassword); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(input.NewPassword)
	if err != nil {
		return domain.NewError("internal_error", "Failed to hash password", 500)
	}

	user.PasswordHash = &hash
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to update password", 500)
	}

	if input.ExceptSessionID != "" {
		if err := s.sessions.DeleteAllForUserExcept(ctx, input.UserID, input.ExceptSessionID); err != nil {
			return domain.NewError("internal_error", "Failed to revoke sessions", 500)
		}
	} else {
		if err := s.sessions.DeleteAllForUser(ctx, input.UserID); err != nil {
			return domain.NewError("internal_error", "Failed to revoke sessions", 500)
		}
	}

	return nil
}
