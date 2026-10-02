package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/port"
)

// VerificationService manages email verification.
type VerificationService struct {
	users     port.UserRepository
	tokens    port.TokenRepository
	gen       port.TokenGenerator
	mailer    port.Mailer
	txManager port.TxManager
	templates port.TemplateProvider
	config    Config
	log       *slog.Logger
	audit     AuditPublisher
	recovery  port.RecoveryEnqueuer
}

// NewVerificationService returns an email verification service.
func NewVerificationService(
	users port.UserRepository,
	tokens port.TokenRepository,
	gen port.TokenGenerator,
	mailer port.Mailer,
	txManager port.TxManager,
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
		txManager: txManager,
		templates: resolveTemplates(config.TemplateProvider, config.URLValidator),
		config:    config,
		log:       logger,
		audit:     config.Audit,
	}
}

// VerifyEmail verifies an email address with a code.
func (s *VerificationService) VerifyEmail(ctx context.Context, code string) (*domain.User, error) {
	// The verification code is an 8-char OTP (~40 bits): low-entropy, so the
	// stored value is HMAC-SHA256(OTPPepper, code), not raw SHA-256. This
	// endpoint takes a bare code with no challenge ID, so unlike 2FA Verify it
	// cannot fetch by ID first — the DB lookup below is a locator only. The
	// security decision happens in app code via verifyOTP (hmac.Equal,
	// constant-time); a row found by the index but failing that check is
	// rejected. Offline cracking of a DB dump still needs the pepper, and
	// online guessing is bounded by code TTL plus the per-IP rate limit (this
	// flow is deliberately not per-token attempt-capped, see below).
	if len(s.config.OTPPepper) == 0 {
		s.log.Error("email verification refused: no OTP pepper derived — refusing")
		return nil, domain.ErrInternal
	}
	token, err := s.tokens.GetByHash(ctx, hashOTP(code, s.config.OTPPepper))
	if err != nil {
		return nil, fmt.Errorf("verify email: lookup: %w", err)
	}
	if token == nil {
		return nil, domain.ErrVerificationCodeInvalid
	}

	if token.Type != domain.TokenVerifyEmail {
		return nil, domain.ErrVerificationCodeInvalid
	}

	if token.UsedAt != nil {
		return nil, domain.ErrVerificationCodeUsed
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, domain.ErrVerificationCodeExpired
	}

	// A rotation-stale code predates the live pepper and can never verify —
	// the old pepper is gone, so the HMAC below couldn't distinguish right
	// from wrong anyway. Answer expired (resend, don't retry) without running
	// it. code_expired vs code_invalid is the client's resend-vs-retype
	// branch, so the two must stay distinct here.
	if stalePepper(token.CreatedAt, s.config.PepperRotatedAt) {
		return nil, domain.ErrVerificationCodeExpired
	}

	if !verifyOTP(code, token.TokenHash, s.config.OTPPepper) {
		return nil, domain.ErrVerificationCodeInvalid
	}

	if token.UserID == nil {
		return nil, domain.ErrVerificationCodeInvalid
	}

	// Not attempt-capped, and it cannot be with this lookup: VerifyEmail
	// resolves the token by hash, so a wrong code finds no row and there is
	// nothing to count against. Per-token attempt capping requires the client
	// to name the token it is guessing at — which is precisely why the 2FA
	// flow exposes a challenge id. Brute-force resistance here rests on the
	// 8-char alphanumeric space (32^8) plus the per-IP rate limit.
	user, err := s.users.GetByID(ctx, *token.UserID)
	if err != nil {
		return nil, fmt.Errorf("verify email: lookup: %w", err)
	}
	if user == nil {
		return nil, domain.ErrUserNotFound
	}

	now := time.Now().UTC()
	verifiedUser := *user
	verifiedUser.IsVerified = true
	verifiedUser.VerifiedAt = &now
	verifiedUser.UpdatedAt = now

	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		consumed, consumeErr := s.tokens.ConsumeIfValid(txCtx, port.ConsumeTokenInput{
			ID:        token.ID,
			TokenHash: token.TokenHash,
			UserID:    user.ID,
			Type:      domain.TokenVerifyEmail,
			UsedAt:    now,
		})
		if consumeErr != nil {
			return consumeErr
		}
		if !consumed {
			return domain.ErrVerificationCodeUsed
		}
		updated, updateErr := verifyUserEmail(txCtx, s.users, user, token.Email, now)
		if updateErr != nil {
			return updateErr
		}
		if !updated {
			return domain.ErrVerificationCodeInvalid
		}
		// Inside the transaction: the record commits with the verification
		// it describes (record-iff-commit). Recording after commit would
		// leave a crash window where the email is verified and no record
		// exists.
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewEmailVerifiedEvent(user.ID)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		var authErr *domain.AuthError
		if errors.As(err, &authErr) {
			return nil, authErr
		}
		s.log.Error("failed to commit email verification", "err", err, "user_id", user.ID, "token_id", token.ID)
		return nil, domain.ErrInternal
	}

	s.log.Info("email verified", "user_id", user.ID, "email", user.Email)

	return &verifiedUser, nil
}

// SendVerification mails a verification code, skipping the send when one is
// already outstanding. The returned api.VerificationResult says which happened;
// a nil error alone does not mean an email left the building.
func (s *VerificationService) SendVerification(ctx context.Context, user *domain.User) (*api.VerificationResult, error) {
	return s.sendVerification(ctx, user, false)
}

func (s *VerificationService) sendVerification(ctx context.Context, user *domain.User, retry bool) (*api.VerificationResult, error) {
	if s.mailer == nil {
		return nil, domain.ErrEmailNotConfigured
	}

	// One read answers both skip questions, the way TwoFactorService.Challenge
	// does it. Checking only the newest token is not a narrowing: a token is
	// minted only when none is outstanding, so a live one is always the newest.
	// (Two concurrent sends can both pass and mint two; the loser then goes
	// unnoticed once the winner is used, which costs one extra email and
	// nothing else.)
	if user.ID != "" && !retry {
		last, err := s.tokens.GetLastByUserAndType(ctx, user.ID, domain.TokenVerifyEmail)
		if err != nil {
			return nil, domain.ErrInternal
		}
		if last != nil {
			// Still usable — reuse it rather than mail a second code.
			if last.UsedAt == nil && time.Now().UTC().Before(last.ExpiresAt) {
				// A live but rotation-stale code can never verify, and
				// reusing it would hand the caller a dead code that
				// VerifyEmail can only answer expired to. Clear it and fall
				// through to the mint below instead of stacking a second
				// row or throttling against a deleted one.
				if stalePepper(last.CreatedAt, s.config.PepperRotatedAt) {
					if derr := s.tokens.DeleteUnusedByUserAndType(ctx, user.ID, domain.TokenVerifyEmail); derr != nil {
						s.log.Error("failed to clear rotation-stale verification token", "err", derr, "user_id", user.ID)
						return nil, domain.ErrInternal
					}
				} else {
					return &api.VerificationResult{Sent: false, ExpiresAt: last.ExpiresAt}, nil
				}
			} else if s.config.VerificationResendInterval > 0 &&
				time.Since(last.CreatedAt) < s.config.VerificationResendInterval {
				// Spent or expired, but minted moments ago: throttle the refresh.
				return &api.VerificationResult{Sent: false, ExpiresAt: last.ExpiresAt}, nil
			}
		}
	}

	raw, err := otp.Generate(8)
	if err != nil {
		s.log.Error("failed to generate verification code", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	if len(s.config.OTPPepper) == 0 {
		s.log.Error("verification send refused: no OTP pepper derived — refusing")
		return nil, domain.ErrInternal
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashOTP(raw, s.config.OTPPepper),
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
		if err := s.audit.Record(ctx, audit.NewEmailVerificationSentEvent(user.Email)); err != nil {
			return nil, err
		}
	}

	return &api.VerificationResult{Sent: true, ExpiresAt: token.ExpiresAt}, nil
}

// ResendVerification sends a user's verification code again.
func (s *VerificationService) ResendVerification(ctx context.Context, userID string) (*api.VerificationResult, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("resend verification: lookup: %w", err)
	}
	if user == nil {
		return nil, domain.ErrUserNotFound
	}

	if user.IsVerified {
		return nil, domain.NewError("already_verified", "Email is already verified")
	}

	return s.SendVerification(ctx, user)
}

// SendVerificationByEmail queues a public request without looking up an account.
// The result never reports whether a message will actually be delivered.
func (s *VerificationService) SendVerificationByEmail(ctx context.Context, email string) (*api.VerificationResult, error) {
	if s.mailer == nil {
		return nil, domain.ErrEmailNotConfigured
	}
	if s.recovery == nil {
		return nil, domain.ErrInternal
	}
	if err := enqueueRecovery(ctx, s.recovery, port.RecoveryVerification, email, s.log); err != nil {
		return nil, err
	}
	return nil, domain.ErrVerificationEmailSent
}

func (s *VerificationService) processVerificationByEmail(ctx context.Context, email string, retry bool) (*api.VerificationResult, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, domain.ErrVerificationEmailSent
	}

	if user.IsVerified {
		return nil, domain.ErrVerificationEmailSent
	}

	return s.sendVerification(ctx, user, retry)
}

func (s *VerificationService) sendVerificationByEmail(ctx context.Context, email string, retry bool) error {
	_, err := s.processVerificationByEmail(ctx, email, retry)
	if errors.Is(err, domain.ErrVerificationEmailSent) {
		return nil
	}
	return err
}
