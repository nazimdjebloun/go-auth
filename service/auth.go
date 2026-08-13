package service

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/port"
)

const deleteAccountCodeTTL = 10 * time.Minute

type AuthService struct {
	users     port.UserRepository
	sessions  port.SessionRepository
	tokens    port.TokenRepository
	hasher    port.Hasher
	gen       port.TokenGenerator
	mailer    port.Mailer
	templates port.TemplateProvider
	config    Config
	log       *slog.Logger
	audit     AuditPublisher

	sessionSvc   *SessionService
	verifySvc    *VerificationService
	twoFactorSvc *TwoFactorService
}

type Config struct {
	AppName                    string
	BaseURL                    string
	InviteOnly                 bool
	EnableEmailPassword        bool
	EnableOAuth                bool
	EnableInvite               bool
	RequireEmailVerification   bool
	InviteTTL                  time.Duration
	VerificationCodeTTL        time.Duration
	VerificationResendInterval time.Duration
	SessionTTL                 time.Duration
	TokenTTL                   time.Duration
	PasswordPolicy             domain.PasswordPolicy
	TemplateProvider           port.TemplateProvider
	URLValidator               *port.URLValidator
	Logger                     *slog.Logger
	Audit                      AuditPublisher

	RequireEmail2FA         bool
	DefaultTwoFactorEnabled bool
	TwoFactorCodeTTL        time.Duration

	// DisableAdminTwoFactor turns off AdminLogin's unconditional email
	// two-factor challenge. See the scope note on AdminLogin.
	DisableAdminTwoFactor bool

	// TwoFactorBindingKey signs 2FA challenge binding tokens. It is a
	// purpose-derived subkey from internal/keyring, never the raw app secret:
	// the keyring exists so each consumer of the secret gets its own key under
	// a versioned info string, the way CSRF signing already does. Empty means
	// no key was derived, and the signer fails closed rather than signing with
	// nothing.
	TwoFactorBindingKey []byte

	DisableTwoFactorChallengeBinding bool
	TwoFactorChallengeCookieName     string
}

type AuditPublisher interface {
	Publish(ctx context.Context, event audit.Event)
}

func NewAuthService(
	users port.UserRepository,
	sessions port.SessionRepository,
	tokens port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	mailer port.Mailer,
	config Config,
	sessionSvc *SessionService,
	verifySvc *VerificationService,
	twoFactorSvc *TwoFactorService,
) *AuthService {
	if config.PasswordPolicy.MinLength == 0 {
		config.PasswordPolicy.MinLength = 8
	}
	if !config.PasswordPolicy.RequireDigit && !config.PasswordPolicy.RequireUppercase && !config.PasswordPolicy.RequireSpecial {
		config.PasswordPolicy.RequireDigit = true
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &AuthService{
		users:        users,
		sessions:     sessions,
		tokens:       tokens,
		hasher:       hasher,
		gen:          gen,
		mailer:       mailer,
		templates:    resolveTemplates(config.TemplateProvider, config.URLValidator),
		config:       config,
		log:          config.Logger,
		audit:        config.Audit,
		sessionSvc:   sessionSvc,
		verifySvc:    verifySvc,
		twoFactorSvc: twoFactorSvc,
	}
}

// enforceTwoFactor reports whether this login must stop for a second factor.
// Nil-guarded: a consumer wiring AuthService directly without the 2FA service
// gets today's behaviour rather than a panic.
func (s *AuthService) enforceTwoFactor(user *domain.User) bool {
	return s.twoFactorSvc != nil && s.twoFactorSvc.Enforce(user)
}

func (s *AuthService) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	if !s.config.EnableEmailPassword {
		return nil, domain.ErrMethodDisabled
	}
	if s.config.InviteOnly {
		return nil, domain.ErrForbidden
	}

	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}
	if err := s.config.PasswordPolicy.Validate(input.Password); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, domain.NewError("name_required", "Name is required")
	}
	input.Name = strings.TrimSpace(input.Name)

	existing, _ := s.users.GetByEmail(ctx, input.Email)
	if existing != nil {
		return nil, domain.ErrEmailAlreadyExists
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		s.log.Error("failed to hash password", "err", err)
		return nil, domain.ErrInternal
	}

	now := time.Now().UTC()

	user := &domain.User{
		ID:               uuid.New().String(),
		Email:            input.Email,
		PasswordHash:     &hash,
		Name:             input.Name,
		Role:             domain.RoleUser,
		IsBanned:         false,
		TwoFactorEnabled: s.config.DefaultTwoFactorEnabled,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		if errors.Is(err, port.ErrDuplicateKey) {
			// The GetByEmail check above lost a race — another request
			// created this email between the check and this Create. The
			// unique constraint is the real backstop; this just makes the
			// loser's response match what GetByEmail would have found.
			return nil, domain.ErrEmailAlreadyExists
		}
		s.log.Error("failed to create user", "err", err, "email", input.Email)
		return nil, domain.ErrInternal
	}

	s.log.Info("user registered", "user_id", user.ID, "email", user.Email)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewUserRegisteredEvent(user.ID, net.ParseIP(input.IP), input.UserAgent))
	}

	if s.config.RequireEmailVerification {
		if _, err := s.verifySvc.SendVerification(ctx, user); err != nil {
			return nil, err
		}
		return &RegisterResult{
			User:                 user,
			RequiresVerification: true,
		}, nil
	}

	// Registration gates on the global flag only, not on the effective check.
	// With DefaultTwoFactorEnabled the new account already has the flag set,
	// yet still gets a session here — the code would go to the address they
	// just typed in, so it proves nothing at registration time. The gate first
	// applies on their next login. Intentional; do not "fix" to enforceTwoFactor.
	if s.config.RequireEmail2FA && s.twoFactorSvc != nil {
		challenge, aerr := s.twoFactorSvc.Challenge(ctx, user.ID)
		if aerr != nil {
			return nil, aerr
		}
		return &RegisterResult{
			User:               user,
			RequiresTwoFactor:  true,
			CodeSent:           challenge.Sent,
			TwoFactorChallenge: challenge.ID,
			TwoFactorExpiresAt: challenge.ExpiresAt,
			bindingToken:       challenge.BindingToken,
		}, nil
	}

	sessResult, err := s.sessionSvc.Create(ctx, user.ID, input.IP, input.UserAgent)
	if err != nil {
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	return &RegisterResult{
		User:         user,
		Session:      sessResult.Session,
		SessionToken: sessResult.SessionToken,
		RefreshToken: sessResult.RefreshToken,
	}, nil
}

// authenticate resolves and validates email/password credentials.
// On success it returns the authenticated user. requiresVerification is true
// when the user must verify their email before a session can be issued.
func (s *AuthService) authenticate(ctx context.Context, input LoginInput) (*domain.User, bool, error) {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	user, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil || user == nil {
		// Constant-time: dummy bcrypt prevents timing-based email enumeration
		_ = s.hasher.Compare(input.Password, "$2a$12$.....................................................................................................")
		return nil, false, domain.ErrInvalidCredentials
	}

	if user.IsBanned {
		return nil, false, domain.ErrUserBanned
	}

	if s.config.RequireEmailVerification && !user.IsVerified && user.Role != domain.RoleAdmin {
		return user, true, nil
	}

	if !user.HasPassword() {
		return nil, false, domain.ErrInvalidCredentials
	}
	if err := s.hasher.Compare(input.Password, *user.PasswordHash); err != nil {
		return nil, false, domain.ErrInvalidCredentials
	}

	return user, false, nil
}

func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	user, requiresVerification, aerr := s.authenticate(ctx, input)
	if aerr != nil {
		return nil, aerr
	}
	if requiresVerification {
		return &LoginResult{
			User:                 user,
			RequiresVerification: true,
		}, nil
	}

	// Ordering: banned → email-verify → password → 2FA → session.
	if s.enforceTwoFactor(user) {
		challenge, aerr := s.twoFactorSvc.Challenge(ctx, user.ID)
		if aerr != nil {
			return nil, aerr
		}
		return &LoginResult{
			User:               user,
			RequiresTwoFactor:  true,
			CodeSent:           challenge.Sent,
			TwoFactorChallenge: challenge.ID,
			TwoFactorExpiresAt: challenge.ExpiresAt,
			bindingToken:       challenge.BindingToken,
		}, nil
	}

	sessResult, err := s.sessionSvc.Create(ctx, user.ID, input.IP, input.UserAgent)
	if err != nil {
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	if err := s.users.UpdateLastLoginAt(ctx, user.ID, time.Now().UTC()); err != nil {
		s.log.Error("failed to update last login time", "err", err, "user_id", user.ID)
	}

	s.log.Info("user logged in", "user_id", user.ID, "ip", input.IP)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewLoginEvent(user.ID, sessResult.Session.ID, net.ParseIP(input.IP), input.UserAgent, true))
	}

	return &LoginResult{
		User:         user,
		Session:      sessResult.Session,
		SessionToken: sessResult.SessionToken,
		RefreshToken: sessResult.RefreshToken,
	}, nil
}

// AdminLogin authenticates a user and requires the admin role.
// Non-admin users are rejected with generic invalid_credentials so the
// endpoint never reveals whether an account is an admin.
func (s *AuthService) AdminLogin(ctx context.Context, input LoginInput) (*LoginResult, error) {
	user, requiresVerification, aerr := s.authenticate(ctx, input)
	if aerr != nil {
		if s.audit != nil {
			s.audit.Publish(ctx, audit.NewAdminLoginFailedEvent(input.Email, net.ParseIP(input.IP), input.UserAgent))
		}
		return nil, aerr
	}

	if requiresVerification || user.Role != domain.RoleAdmin {
		if s.audit != nil {
			s.audit.Publish(ctx, audit.NewAdminLoginFailedEvent(input.Email, net.ParseIP(input.IP), input.UserAgent))
		}
		return nil, domain.ErrInvalidCredentials
	}

	// /auth/admin/login requires a second factor by default. Not
	// s.enforceTwoFactor: this is independent of RequireEmail2FA and of the
	// user's own TwoFactorEnabled flag. Applied after the role rejection above
	// so the admin-vs-not distinction still leaks nothing.
	//
	// Scope note: this gates the endpoint, not the account. An admin signing in
	// through /auth/login gets the ordinary check, and the session issued there
	// carries role:admin just the same — so this raises the bar on the admin
	// route specifically rather than guaranteeing every admin session cleared a
	// second factor. Pair it with RequireEmail2FA, or with the admin enabling
	// 2FA on their own account, if you want that stronger property.
	//
	// DisableAdminTwoFactor opts out entirely, for API-only deployments with
	// no mailer configured — NewConfig refuses that combination unless every
	// other email-sending feature is also off.
	if !s.config.DisableAdminTwoFactor && s.twoFactorSvc != nil {
		challenge, aerr := s.twoFactorSvc.Challenge(ctx, user.ID)
		if aerr != nil {
			return nil, aerr
		}
		return &LoginResult{
			User:               user,
			RequiresTwoFactor:  true,
			CodeSent:           challenge.Sent,
			TwoFactorChallenge: challenge.ID,
			TwoFactorExpiresAt: challenge.ExpiresAt,
			bindingToken:       challenge.BindingToken,
		}, nil
	}

	sessResult, err := s.sessionSvc.Create(ctx, user.ID, input.IP, input.UserAgent)
	if err != nil {
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	if err := s.users.UpdateLastLoginAt(ctx, user.ID, time.Now().UTC()); err != nil {
		s.log.Error("failed to update last login time", "err", err, "user_id", user.ID)
	}

	s.log.Info("admin logged in", "user_id", user.ID, "ip", input.IP)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewAdminLoginSuccessEvent(user.ID, sessResult.Session.ID, net.ParseIP(input.IP), input.UserAgent))
	}

	return &LoginResult{
		User:         user,
		Session:      sessResult.Session,
		SessionToken: sessResult.SessionToken,
		RefreshToken: sessResult.RefreshToken,
	}, nil
}

func (s *AuthService) ValidateSession(ctx context.Context, tokenRaw string) (*domain.User, *domain.Session, error) {
	session, err := s.sessionSvc.Validate(ctx, tokenRaw)
	if err != nil {
		return nil, nil, domain.ErrSessionExpired
	}

	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil || user == nil {
		return nil, nil, domain.ErrSessionExpired
	}
	if user.IsBanned {
		return nil, nil, domain.ErrUserBanned
	}

	return user, session, nil
}

func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	if err := s.sessionSvc.RevokeByID(ctx, sessionID); err != nil {
		s.log.Error("failed to revoke session", "err", err, "session_id", sessionID)
		return domain.ErrInternal
	}
	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewLogoutEvent("", sessionID, nil, ""))
	}
	return nil
}

func (s *AuthService) ChangeName(ctx context.Context, userID, newName string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}
	if newName == "" {
		return domain.NewError("validation_error", "Name cannot be empty")
	}
	user.Name = newName
	user.UpdatedAt = time.Now().UTC()
	if err := s.users.Update(ctx, user); err != nil {
		s.log.Error("failed to update name", "err", err, "user_id", userID)
		return domain.ErrInternal
	}
	s.log.Info("name changed", "user_id", userID)
	return nil
}

func (s *AuthService) DeleteAccount(ctx context.Context, userID string, password string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if !user.HasPassword() {
		return domain.ErrPasswordRequired
	}
	if err := s.hasher.Compare(password, *user.PasswordHash); err != nil {
		return domain.NewError("wrong_password", "Password is incorrect")
	}

	if err := s.sessions.DeleteAllForUser(ctx, userID); err != nil {
		s.log.Error("failed to revoke sessions", "err", err, "user_id", userID)
		return domain.ErrInternal
	}

	if err := s.users.Delete(ctx, userID); err != nil {
		s.log.Error("failed to delete user", "err", err, "user_id", userID)
		return domain.ErrInternal
	}

	s.log.Info("account deleted", "user_id", userID)
	return nil
}

func (s *AuthService) RequestDeleteAccount(ctx context.Context, userID string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if user.HasPassword() {
		return domain.NewError("password_account", "Use DELETE /auth/account with password to delete your account")
	}

	if s.mailer == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured")
	}

	hasValid, err := s.tokens.HasValidByUserAndType(ctx, userID, domain.TokenDeleteAccount)
	if err == nil && hasValid {
		return nil
	}

	raw, err := otp.Generate(8)
	if err != nil {
		s.log.Error("failed to generate deletion code", "err", err, "user_id", userID)
		return domain.ErrInternal
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(raw),
		Type:      domain.TokenDeleteAccount,
		ExpiresAt: now.Add(deleteAccountCodeTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		s.log.Error("failed to store deletion token", "err", err, "user_id", userID)
		return domain.ErrInternal
	}

	result, err := s.templates.Render(port.DeleteAccountData{
		AppName:   s.config.AppName,
		Code:      raw,
		ExpiresIn: deleteAccountCodeTTL,
	})
	if err != nil {
		s.log.Error("failed to render deletion email template", "err", err, "user_id", userID)
		return domain.ErrInternal
	}

	if err := s.mailer.Send(ctx, user.Email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send deletion email", "err", err, "user_id", userID)
		return domain.NewError("email_failed", "Failed to send deletion email")
	}

	return nil
}

func (s *AuthService) ConfirmDeleteAccount(ctx context.Context, input ConfirmDeleteAccountInput) error {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	token, err := s.tokens.GetByHash(ctx, hashToken(input.Code))
	if err != nil || token == nil {
		return domain.ErrDeleteCodeInvalid
	}

	if token.Type != domain.TokenDeleteAccount {
		return domain.ErrDeleteCodeInvalid
	}

	if token.UsedAt != nil {
		return domain.ErrDeleteCodeAlreadyUsed
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return domain.ErrDeleteCodeExpired
	}

	if token.UserID == nil || *token.UserID != input.UserID {
		return domain.ErrDeleteCodeInvalid
	}

	if err := s.sessions.DeleteAllForUser(ctx, input.UserID); err != nil {
		s.log.Error("failed to revoke sessions", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	if err := s.users.Delete(ctx, input.UserID); err != nil {
		s.log.Error("failed to delete user", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	if err := s.tokens.MarkUsed(ctx, token.ID); err != nil {
		s.log.Error("failed to mark token used", "err", err, "token_id", token.ID)
		return domain.ErrInternal
	}

	s.log.Info("account deleted via code", "user_id", input.UserID)
	return nil
}

func validateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return domain.ErrInvalidEmail
	}
	return nil
}
