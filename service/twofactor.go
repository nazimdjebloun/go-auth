package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// Three counters live in this file. Every name carries its scope, deliberately:
// they are identical in shape — each is "a count compared against a ceiling" —
// and one word apart in a diff, which is how an account-scoped notify threshold
// gets confused for a lineage-scoped blocking cap in a hotfix.
//
//	maxAttemptsPerChallenge      5       one challenge lineage   BLOCKS further guesses on that lineage
//	maxCodeRefreshesPerChallenge 3       one challenge lineage   BLOCKS further resends on that lineage
//	notifyThresholdPerAccount    20/hour the whole account       BLOCKS NOTHING — sends one email
//
// The first two are per-lineage and blocking. The third is per-account and must
// never block. Do not tune them as a group.
const (
	maxAttemptsPerChallenge      = 5
	maxCodeRefreshesPerChallenge = 3
	notifyThresholdPerAccount    = 20
	notifyWindowPerAccount       = time.Hour

	twoFactorCodeLength = 6
)

// TwoFactorService owns email-based second-factor login.
//
// The per-lineage attempt cap here is a per-browser control: a new browser means
// a new login, a new challenge id, and a fresh counter. Its job is bounding
// honest-mistake loops and making each fresh guess budget cost a full login
// round-trip. It is NOT the brute-force control — per-IP rate limiting is, with
// the residual distributed case accepted and documented in docs/security.mdx.
type TwoFactorService struct {
	users      port.UserRepository
	sessions   port.SessionRepository
	tokens     port.TokenRepository
	hasher     port.Hasher
	mailer     port.Mailer
	templates  port.TemplateProvider
	store      ratelimit.Store
	config     Config
	log        *slog.Logger
	audit      AuditPublisher
	sessionSvc *SessionService
}

func NewTwoFactorService(
	users port.UserRepository,
	sessions port.SessionRepository,
	tokens port.TokenRepository,
	hasher port.Hasher,
	mailer port.Mailer,
	store ratelimit.Store,
	config Config,
	sessionSvc *SessionService,
) *TwoFactorService {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &TwoFactorService{
		users:      users,
		sessions:   sessions,
		tokens:     tokens,
		hasher:     hasher,
		mailer:     mailer,
		templates:  resolveTemplates(config.TemplateProvider, config.URLValidator),
		store:      store,
		config:     config,
		log:        logger,
		audit:      config.Audit,
		sessionSvc: sessionSvc,
	}
}

// CookieName, CookieTTL, and BindingDisabled expose just the pieces of Config
// the HTTP layer needs to set/clear the challenge binding cookie, without
// handing it the whole (unexported-field) Config.
func (s *TwoFactorService) CookieName() string       { return s.config.TwoFactorChallengeCookieName }
func (s *TwoFactorService) CookieTTL() time.Duration { return s.config.TwoFactorCodeTTL }
func (s *TwoFactorService) BindingDisabled() bool    { return s.config.DisableTwoFactorChallengeBinding }

// Enforce reports whether a user must clear a second factor to get a session.
//
// This is the ordinary login check. /auth/admin/login enforces unconditionally
// on top of it — see AuthService.AdminLogin.
func (s *TwoFactorService) Enforce(u *domain.User) bool {
	if u == nil {
		return false
	}
	return s.config.RequireEmail2FA || u.TwoFactorEnabled
}

// ─── Challenge ──────────────────────────────────────────────

// Challenge returns a pending 2FA challenge for the user, mailing a code only
// when it has to.
//
// It never refuses. A capped lineage is replaced, not enforced against: the
// attempt cap bounds one lineage, it does not lock the account. An earlier
// design had this refuse until the lineage expired, on the theory that minting
// freely let an attacker with the password buy 5 guesses per login — but
// /auth/2fa/verify's own rate limit binds first, so single-IP throughput is
// 5 guesses/min either way, and the refusal only added an account-level denial
// vector. Do not reintroduce it.
func (s *TwoFactorService) Challenge(ctx context.Context, userID string) (*ChallengeResult, error) {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, domain.ErrUserNotFound
	}

	// Reuse only a lineage that is still usable. The counter checks are
	// load-bearing: nothing marks a capped row used (the guarded writes below
	// are the cap), so a dead lineage is neither used nor expired. Without
	// them the next login would answer "a code was already sent" and point at
	// a challenge that can never verify.
	if existing, err := s.tokens.GetLastByUserAndType(ctx, userID, domain.TokenTwoFactor); err == nil && existing != nil {
		if existing.UsedAt == nil &&
			time.Now().UTC().Before(existing.ExpiresAt) &&
			existing.Attempts < maxAttemptsPerChallenge &&
			existing.ResendCount < maxCodeRefreshesPerChallenge {
			return &ChallengeResult{
				ID:           existing.ID,
				Sent:         false,
				ExpiresAt:    existing.ExpiresAt,
				BindingToken: s.bindingToken(existing.ID),
			}, nil
		}
	}

	if err := s.tokens.DeleteUnusedByUserAndType(ctx, userID, domain.TokenTwoFactor); err != nil {
		s.log.Error("failed to clear stale 2fa tokens", "err", err, "user_id", userID)
		return nil, domain.ErrInternal
	}

	return s.issue(ctx, user)
}

// issue mints a fresh challenge row and mails the code.
func (s *TwoFactorService) issue(ctx context.Context, user *domain.User) (*ChallengeResult, error) {
	if s.mailer == nil {
		return nil, domain.NewError("email_not_configured", "Email sender is not configured")
	}

	raw, err := otp.GenerateNumeric(twoFactorCodeLength)
	if err != nil {
		s.log.Error("failed to generate 2fa code", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(raw),
		Type:      domain.TokenTwoFactor,
		ExpiresAt: now.Add(s.config.TwoFactorCodeTTL),
		CreatedAt: now,
	}
	if err := s.tokens.Create(ctx, token); err != nil {
		s.log.Error("failed to store 2fa token", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	if aerr := s.send(ctx, user, raw); aerr != nil {
		// Undo the mint. Left in place, this row is a live lineage as far as
		// Challenge's reuse check is concerned, so every login for the next
		// TwoFactorCodeTTL would answer "a code was already sent" and hand back
		// a challenge whose code nobody has — locking the account out of login
		// entirely until it expires. Note Challenge's own cleanup cannot save
		// it: the reuse branch returns before reaching that delete.
		//
		// Deleting by user+type rather than by id is safe here because issue is
		// only reached after Challenge cleared the unused rows, so this is the
		// only one. Two concurrent logins can race — the loser's challenge id
		// stops resolving and that login has to be retried, which is the right
		// trade against a guaranteed lockout.
		if derr := s.tokens.DeleteUnusedByUserAndType(ctx, user.ID, domain.TokenTwoFactor); derr != nil {
			s.log.Error("failed to clear undelivered 2fa token", "err", derr, "user_id", user.ID)
		}
		return nil, aerr
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewTwoFactorCodeSentEvent(user.ID))
	}

	return &ChallengeResult{
		ID:           token.ID,
		Sent:         true,
		ExpiresAt:    token.ExpiresAt,
		BindingToken: s.bindingToken(token.ID),
	}, nil
}

func (s *TwoFactorService) send(ctx context.Context, user *domain.User, code string) error {
	if s.mailer == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured")
	}
	result, err := s.templates.Render(port.TwoFactorData{
		AppName:   s.config.AppName,
		Code:      code,
		ExpiresIn: s.config.TwoFactorCodeTTL,
	})
	if err != nil {
		s.log.Error("failed to render 2fa email template", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}
	if err := s.mailer.Send(ctx, user.Email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send 2fa email", "err", err, "user_id", user.ID)
		return domain.NewError("email_failed", "Failed to send two-factor code")
	}
	return nil
}

// ─── Challenge binding ──────────────────────────────────────

// bindingToken ties a challenge id to the client that started it. The handler
// sets it as a cookie; Verify and Resend require it back. Without it a
// challenge id that leaks into a log line or a proxy is a usable half of the
// credential on its own.
//
// Empty when binding is disabled, or when no key was derived — the latter
// fails closed at check time rather than signing with an empty key.
func (s *TwoFactorService) bindingToken(challengeID string) string {
	if s.config.DisableTwoFactorChallengeBinding || len(s.config.TwoFactorBindingKey) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, s.config.TwoFactorBindingKey)
	mac.Write([]byte(challengeID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// checkBinding reports whether the supplied token matches the challenge.
// Fails closed on a missing secret; skipped entirely only when the consumer
// explicitly disabled binding.
func (s *TwoFactorService) checkBinding(challengeID, supplied string) bool {
	if s.config.DisableTwoFactorChallengeBinding {
		return true
	}
	if len(s.config.TwoFactorBindingKey) == 0 {
		s.log.Error("2fa challenge binding enabled but no binding key derived — refusing")
		return false
	}
	want := s.bindingToken(challengeID)
	return subtle.ConstantTimeCompare([]byte(want), []byte(supplied)) == 1
}

// ─── Verify ─────────────────────────────────────────────────

// TwoFactorVerifyResult is Verify's outcome — the authenticated user, the
// newly issued session, and the raw tokens that go with it.
type TwoFactorVerifyResult struct {
	User         *domain.User
	Session      *domain.Session
	SessionToken string
	RefreshToken string
}

// Verify exchanges a challenge id and code for a session.
//
// The cap is enforced by the guarded writes, not by a pre-read: a read-then-
// branch would let a concurrent burst all observe the same pre-increment count
// and all pass the check before any write landed. One consequence is that a
// correct code arriving on an already-capped lineage is rejected too.
func (s *TwoFactorService) Verify(ctx context.Context, challengeID, bindingToken, code, ip, userAgent string) (*TwoFactorVerifyResult, error) {
	if !s.checkBinding(challengeID, bindingToken) {
		return nil, domain.ErrTwoFactorCodeInvalid
	}

	token, err := s.tokens.GetByID(ctx, challengeID)
	if err != nil || token == nil || token.Type != domain.TokenTwoFactor || token.UserID == nil {
		return nil, domain.ErrTwoFactorCodeInvalid
	}
	if token.UsedAt != nil {
		return nil, domain.ErrTwoFactorCodeAlreadyUsed
	}
	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, domain.ErrTwoFactorCodeExpired
	}

	if subtle.ConstantTimeCompare([]byte(hashToken(code)), []byte(token.TokenHash)) != 1 {
		// A false return means the cap was already reached, by an earlier
		// guess or a concurrent one. Either way the caller learns only
		// "invalid" — the distinction is not theirs to see.
		if _, err := s.tokens.IncrementAttempts(ctx, token.ID, maxAttemptsPerChallenge); err != nil {
			s.log.Error("failed to record 2fa attempt", "err", err, "token_id", token.ID)
		}
		s.recordFailure(ctx, *token.UserID, token.Email, ip, userAgent)
		return nil, domain.ErrTwoFactorCodeInvalid
	}

	// Correct code, but claim the lineage under the same cap: a concurrent
	// wrong guess may have tripped it between the comparison above and here.
	ok, err := s.tokens.MarkUsedIfUnderCap(ctx, token.ID, maxAttemptsPerChallenge)
	if err != nil {
		s.log.Error("failed to consume 2fa token", "err", err, "token_id", token.ID)
		return nil, domain.ErrInternal
	}
	if !ok {
		return nil, domain.ErrTwoFactorCodeInvalid
	}

	user, err := s.users.GetByID(ctx, *token.UserID)
	if err != nil || user == nil {
		return nil, domain.ErrUserNotFound
	}

	sessResult, err := s.sessionSvc.Create(ctx, user.ID, ip, userAgent)
	if err != nil {
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	if err := s.users.UpdateLastLoginAt(ctx, user.ID, time.Now().UTC()); err != nil {
		s.log.Error("failed to update last login time", "err", err, "user_id", user.ID)
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewTwoFactorVerifiedEvent(user.ID, sessResult.Session.ID, net.ParseIP(ip), userAgent))
	}

	return &TwoFactorVerifyResult{
		User:         user,
		Session:      sessResult.Session,
		SessionToken: sessResult.SessionToken,
		RefreshToken: sessResult.RefreshToken,
	}, nil
}

// recordFailure publishes the per-attempt audit event and advances the
// account-scoped notify counter.
//
// The counter never blocks. A fixed-threshold blocking counter would not raise
// attacker cost meaningfully — the threshold is trivially reached by anyone
// already scripting this — while handing a cheaper win to a different attacker,
// one who only wants the owner locked out. Tripping a threshold is always
// easier than beating one. Notifying the owner so a known-compromised password
// gets rotated is the outcome that actually matters here.
func (s *TwoFactorService) recordFailure(ctx context.Context, userID, email, ip, userAgent string) {
	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewTwoFactorFailedEvent(userID, net.ParseIP(ip), userAgent))
	}
	if s.store == nil {
		return
	}

	res, err := s.store.Increment("2fa:fail:"+userID, notifyWindowPerAccount)
	if err != nil {
		// Notification is best-effort: it must never fail a login attempt.
		s.log.Error("failed to record 2fa failure count", "err", err, "user_id", userID)
		return
	}
	// Fire once per window, on the crossing itself, not on every later failure.
	if res.Count != notifyThresholdPerAccount {
		return
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewTwoFactorSuspiciousEvent(userID, net.ParseIP(ip), userAgent))
	}
	s.notifySuspicious(ctx, email, res.Count)
}

func (s *TwoFactorService) notifySuspicious(ctx context.Context, email string, count int) {
	if s.mailer == nil {
		return
	}
	result, err := s.templates.Render(port.TwoFactorSuspiciousData{
		AppName:          s.config.AppName,
		AttemptCount:     count,
		ResetPasswordURL: s.config.BaseURL + "/forgot-password",
	})
	if err != nil {
		s.log.Error("failed to render 2fa suspicious-activity email", "err", err)
		return
	}
	if err := s.mailer.Send(ctx, email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send 2fa suspicious-activity email", "err", err)
	}
}

// ─── Resend ─────────────────────────────────────────────────

// Resend refreshes the code on the same challenge row.
//
// Updating in place rather than issuing a new row is what makes the attempt cap
// mean anything: attempts live on that row and are never reset, so once the cap
// is reached the same guard that blocks Verify also blocks further resends.
// The separate resend ceiling bounds how many times one lineage's code can be
// refreshed, which also stops this being an email-bombing amplifier.
func (s *TwoFactorService) Resend(ctx context.Context, challengeID, bindingToken string) (*ChallengeResult, error) {
	vague := domain.NewError("challenge_not_found", "If the challenge is valid, a new code has been sent")

	if !s.checkBinding(challengeID, bindingToken) {
		return nil, vague
	}

	token, err := s.tokens.GetByID(ctx, challengeID)
	if err != nil || token == nil || token.Type != domain.TokenTwoFactor || token.UserID == nil {
		return nil, vague
	}

	user, err := s.users.GetByID(ctx, *token.UserID)
	if err != nil || user == nil {
		return nil, vague
	}
	if s.mailer == nil {
		return nil, domain.NewError("email_not_configured", "Email sender is not configured")
	}

	raw, err := otp.GenerateNumeric(twoFactorCodeLength)
	if err != nil {
		s.log.Error("failed to generate 2fa code", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	expiresAt := time.Now().UTC().Add(s.config.TwoFactorCodeTTL)
	ok, err := s.tokens.UpdateForResend(ctx, token.ID, hashToken(raw), expiresAt,
		maxCodeRefreshesPerChallenge, maxAttemptsPerChallenge)
	if err != nil {
		s.log.Error("failed to refresh 2fa token", "err", err, "token_id", token.ID)
		return nil, domain.ErrInternal
	}
	if !ok {
		// Used, capped, or out of refreshes. Starting over works — Challenge
		// mints a fresh lineage — so say so rather than leaving them stuck.
		return nil, domain.ErrTwoFactorCodeExpired
	}

	// No cleanup on failure here, unlike issue: this row carries the lineage's
	// attempts, and deleting it would hand back a fresh guess budget to anyone
	// who can make a send fail. The undelivered code is recoverable anyway —
	// retrying Resend re-mints on the same row while refreshes remain — which
	// is exactly what a fresh mint is not.
	if aerr := s.send(ctx, user, raw); aerr != nil {
		return nil, aerr
	}
	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewTwoFactorCodeSentEvent(user.ID))
	}

	// The challenge id is unchanged across a resend, so the binding still holds.
	return &ChallengeResult{
		ID:           token.ID,
		Sent:         true,
		ExpiresAt:    expiresAt,
		BindingToken: s.bindingToken(token.ID),
	}, nil
}

// ─── Enable / Disable ───────────────────────────────────────

// Enable turns on per-user 2FA after re-checking the password.
//
// keepOtherSessions is spelled to make the zero value the safe one: an omitted
// JSON bool decodes to false, so "revokeOtherSessions" documented as defaulting
// to true would in fact default to false and silently skip revocation for every
// client that didn't send it. Same reasoning as SecurityConfig.DisableCSRFToken.
func (s *TwoFactorService) Enable(ctx context.Context, userID, password string, keepOtherSessions bool, callerSessionID string) error {
	user, aerr := s.authorizeChange(ctx, userID, password)
	if aerr != nil {
		return aerr
	}
	if user.TwoFactorEnabled {
		return nil
	}

	if err := s.users.SetTwoFactorEnabled(ctx, user.ID, true, time.Now().UTC()); err != nil {
		s.log.Error("failed to enable 2fa", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	// Borrow ChangePassword's call, not its control flow: there, an empty
	// except-id means "revoke everything including the caller". Here opting out
	// must skip revocation entirely, or keepOtherSessions would log the user
	// out of the very session making the request.
	if !keepOtherSessions && callerSessionID != "" {
		if err := s.sessions.DeleteAllForUserExcept(ctx, user.ID, callerSessionID); err != nil {
			s.log.Error("failed to revoke sessions", "err", err, "user_id", user.ID)
			return domain.ErrInternal
		}
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewTwoFactorEnabledEvent(user.ID))
	}
	return nil
}

// Disable turns off per-user 2FA. No session revocation: turning 2FA off is not
// the "someone may be in my account" signal that turning it on is.
func (s *TwoFactorService) Disable(ctx context.Context, userID, password string) error {
	user, aerr := s.authorizeChange(ctx, userID, password)
	if aerr != nil {
		return aerr
	}
	if !user.TwoFactorEnabled {
		return nil
	}

	if err := s.users.SetTwoFactorEnabled(ctx, user.ID, false, time.Now().UTC()); err != nil {
		s.log.Error("failed to disable 2fa", "err", err, "user_id", user.ID)
		return domain.ErrInternal
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewTwoFactorDisabledEvent(user.ID))
	}
	return nil
}

// authorizeChange gates both Enable and Disable: mandatory 2FA cannot be
// toggled at all, and either direction needs the password re-checked. The
// password check is what stops an OAuth-authenticated session — which never
// passed a second factor — from switching 2FA off.
func (s *TwoFactorService) authorizeChange(ctx context.Context, userID, password string) (*domain.User, error) {
	if s.config.RequireEmail2FA {
		return nil, domain.ErrTwoFactorAlreadyEnforced
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, domain.ErrUserNotFound
	}
	if !user.HasPassword() {
		return nil, domain.ErrTwoFactorPasswordRequired
	}
	if password == "" {
		return nil, domain.ErrTwoFactorPasswordRequired
	}
	if err := s.hasher.Compare(password, *user.PasswordHash); err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	return user, nil
}
