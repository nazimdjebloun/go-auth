package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/port"
)

type VerificationService struct {
	users     port.UserRepository
	tokens    port.TokenRepository
	gen       port.TokenGenerator
	mailer    port.Mailer
	templates port.TemplateProvider
	config    Config
	log       *slog.Logger
	audit     AuditPublisher
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
		users:     users,
		tokens:    tokens,
		gen:       gen,
		mailer:    mailer,
		templates: resolveTemplates(config.TemplateProvider, config.URLValidator),
		config:    config,
		log:       logger,
		audit:     config.Audit,
	}
}

func (s *VerificationService) VerifyEmail(ctx context.Context, code string) (*domain.User, error) {
	token, err := s.tokens.GetByHash(ctx, hashToken(code))
	if err != nil || token == nil {
		return nil, domain.NewError("code_invalid", "Invalid verification code")
	}

	if token.Type != domain.TokenVerifyEmail {
		return nil, domain.NewError("code_invalid", "Invalid verification code")
	}

	if token.UsedAt != nil {
		return nil, domain.NewError("code_already_used", "This code has already been used")
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, domain.NewError("code_expired", "Verification code has expired")
	}

	if token.UserID == nil {
		return nil, domain.NewError("code_invalid", "Invalid verification code")
	}

	// Not attempt-capped, and it cannot be with this lookup: VerifyEmail
	// resolves the token by hash, so a wrong code finds no row and there is
	// nothing to count against. Per-token attempt capping requires the client
	// to name the token it is guessing at — which is precisely why the 2FA
	// flow exposes a challenge id. Brute-force resistance here rests on the
	// 8-char alphanumeric space (32^8) plus the per-IP rate limit.
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
		return nil, domain.ErrInternal
	}

	if err := s.tokens.MarkUsed(ctx, token.ID); err != nil {
		s.log.Error("failed to mark token used", "err", err, "token_id", token.ID)
		return nil, domain.ErrInternal
	}

	s.log.Info("email verified", "user_id", user.ID, "email", user.Email)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewEmailVerifiedEvent(user.ID))
	}

	return user, nil
}

// SendVerification mails a verification code, skipping the send when one is
// already outstanding. The returned VerificationResult says which happened;
// a nil error alone does not mean an email left the building.
func (s *VerificationService) SendVerification(ctx context.Context, user *domain.User) (*VerificationResult, error) {
	if s.mailer == nil {
		return nil, domain.NewError("email_not_configured", "Email sender is not configured")
	}

	// One read answers both skip questions, the way TwoFactorService.Challenge
	// does it. Checking only the newest token is not a narrowing: a token is
	// minted only when none is outstanding, so a live one is always the newest.
	// (Two concurrent sends can both pass and mint two; the loser then goes
	// unnoticed once the winner is used, which costs one extra email and
	// nothing else.)
	if user.ID != "" {
		last, err := s.tokens.GetLastByUserAndType(ctx, user.ID, domain.TokenVerifyEmail)
		if err == nil && last != nil {
			// Still usable — reuse it rather than mail a second code.
			if last.UsedAt == nil && time.Now().UTC().Before(last.ExpiresAt) {
				return &VerificationResult{Sent: false, ExpiresAt: last.ExpiresAt}, nil
			}
			// Spent or expired, but minted moments ago: throttle the refresh.
			if s.config.VerificationResendInterval > 0 &&
				time.Since(last.CreatedAt) < s.config.VerificationResendInterval {
				return &VerificationResult{Sent: false, ExpiresAt: last.ExpiresAt}, nil
			}
		}
	}

	raw, err := otp.Generate(8)
	if err != nil {
		s.log.Error("failed to generate verification code", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(raw),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(s.config.VerificationCodeTTL),
		// Set here, not left to the repository's backfill: the resend throttle
		// above reads CreatedAt, so the value has to exist for every store.
		CreatedAt: now,
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		s.log.Error("failed to store verification token", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	ttl := s.config.VerificationCodeTTL
	result, err := s.templates.Render(port.VerificationData{
		AppName:   s.config.AppName,
		Code:      raw,
		ExpiresIn: ttl,
	})
	if err != nil {
		s.log.Error("failed to render verification email template", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	if err := s.mailer.Send(ctx, user.Email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send verification email", "err", err, "user_id", user.ID)
		// Drop the row the failed send would otherwise leave behind. An
		// undelivered code is indistinguishable from an outstanding one to the
		// skip check above, so keeping it would make the next call answer "a
		// code was already sent" about a code that never left — for the whole
		// VerificationCodeTTL, with resend hitting the same branch. Clearing it
		// is what lets Sent=false mean a code the mailer actually accepted.
		if derr := s.tokens.DeleteUnusedByUserAndType(ctx, user.ID, domain.TokenVerifyEmail); derr != nil {
			s.log.Error("failed to clear undelivered verification token", "err", derr, "user_id", user.ID)
		}
		return nil, domain.NewError("email_failed", "Failed to send verification email")
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewEmailVerificationSentEvent(user.Email))
	}

	return &VerificationResult{Sent: true, ExpiresAt: token.ExpiresAt}, nil
}

func (s *VerificationService) ResendVerification(ctx context.Context, userID string) (*VerificationResult, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, domain.ErrUserNotFound
	}

	if user.IsVerified {
		return nil, domain.NewError("already_verified", "Email is already verified")
	}

	return s.SendVerification(ctx, user)
}

// SendVerificationByEmail resolves the account itself and is safe to expose
// unauthenticated. Its result must not reach the caller — Sent would report
// whether an unverified account exists for that address, which is exactly what
// the flat "if an account exists" reply is there to withhold. See the handler.
func (s *VerificationService) SendVerificationByEmail(ctx context.Context, email string) (*VerificationResult, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, domain.NewError("email_not_found", "If an account exists, a verification email has been sent")
	}

	if user.IsVerified {
		return nil, domain.NewError("email_not_found", "If an account exists, a verification email has been sent")
	}

	return s.SendVerification(ctx, user)
}
