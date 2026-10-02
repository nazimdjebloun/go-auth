package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher/registry"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/port"
)

const deleteAccountCodeTTL = 10 * time.Minute

// AuthService provides registration and authentication operations.
type AuthService struct {
	users     port.UserRepository
	sessions  port.SessionRevoker // only DeleteAllForUser (account deletion)
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

	// deletion carries the transactional account-deletion invariants. It is
	// attached by the library's wiring; see AccountDeletion for why it can
	// legitimately be nil (mock-built services).
	deletion *AccountDeletion

	// txManager commits authentication/session mutations and their audit
	// records together (record-iff-commit). It is nil only in lightweight
	// mock-built services; production wiring always attaches it.
	txManager port.TxManager
}

// AttachTxManager wires the transaction manager used by registration,
// successful login session issuance, and logout so each mutation is atomic
// with the audit records that describe it. Called once by library wiring.
func (s *AuthService) AttachTxManager(tm port.TxManager) {
	s.txManager = tm
}

func (s *AuthService) withTx(ctx context.Context, fn func(context.Context) error) error {
	if s.txManager == nil {
		return fn(ctx)
	}
	return s.txManager.WithTx(ctx, fn)
}

// AttachAccountDeletion wires the shared transactional account-deletion
// coordinator into this service. Called by the library's own construction;
// safe to call once, before the service handles requests.
func (s *AuthService) AttachAccountDeletion(d *AccountDeletion) {
	s.deletion = d
}

// Config configures AuthService.
type Config struct {
	CommonConfig

	InviteOnly                 bool
	EnableEmailPassword        bool
	EnableOAuth                bool
	EnableInvite               bool
	RequireEmailVerification   bool
	InviteTTL                  time.Duration
	VerificationCodeTTL        time.Duration
	VerificationResendInterval time.Duration
	PasswordPolicy             domain.PasswordPolicy
	TemplateProvider           port.TemplateProvider
	URLValidator               *port.URLValidator

	RequireEmail2FA         bool
	DefaultTwoFactorEnabled bool
	TwoFactorCodeTTL        time.Duration

	// DisableAdminTwoFactor opts out of the default admin-account requirement.
	// Global and per-user requirements still apply.
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

	// OTPPepper peppers every low-entropy code/OTP (6-digit 2FA codes,
	// 8-char verification / set-password / delete-account codes) via
	// HMAC-SHA256 before storage. It is keyring's OTPPepper subkey
	// ("goauth-otp-pepper-v1") — a distinct purpose string from
	// TwoFactorBindingKey and from any password pepper, never the raw app
	// secret. Empty fails closed at verify/store time. High-entropy tokens
	// (session, reset, invite, OAuth state) do not use it; see token.go.
	OTPPepper []byte

	// PepperRotatedAt is when the current OTPPepper became live, operator-set
	// via WithPepperRotatedAt to the same UTC value on every instance (see
	// SecurityConfig.PepperRotatedAt). A stored code issued before it was
	// hashed under a gone pepper and can never verify, so verifiers answer
	// expired-style (resend, don't retry) without running the HMAC or burning
	// attempt budget — see stalePepper. Zero (never configured) disables the
	// stale branch: verification is purely by HMAC. It must be operator-set
	// rather than boot-stamped so instances behind a load balancer agree —
	// per-process timestamps would disagree during rolling deploys.
	PepperRotatedAt time.Time
}

// AuditPublisher records audit events.
type AuditPublisher interface {
	// Record writes the event durably: the audit record joins the caller's
	// transaction (record-iff-commit) and, when external delivery sinks are
	// configured, so does the delivery obligation. A non-nil error means the
	// enqueue failure mode is fail-closed and the operation must abort —
	// which, outside a transaction, degrades to fail-open by design.
	Record(ctx context.Context, event audit.Event) error
}

// NewAuthService returns an authentication service.
func NewAuthService(
	users port.UserRepository,
	sessions port.SessionRevoker,
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

// createAuditedLoginSession commits the new session and the login-success
// record together. SessionService also records session.created using the same
// transaction context, so both records obey record-iff-commit.
func (s *AuthService) createAuditedLoginSession(
	ctx context.Context,
	user *domain.User,
	ip, userAgent string,
	loginEvent func(sessionID string) audit.Event,
) (*api.SessionResult, error) {
	var result *api.SessionResult
	err := s.withTx(ctx, func(txCtx context.Context) error {
		if _, err := lockPasswordIdentity(txCtx, s.users, user); err != nil {
			return err
		}
		created, err := s.sessionSvc.Create(txCtx, user.ID, ip, userAgent)
		if err != nil {
			return err
		}
		if s.audit != nil && loginEvent != nil {
			if err := s.audit.Record(txCtx, loginEvent(created.Session.ID)); err != nil {
				return err
			}
		}
		result = created
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Register creates a user account.
func (s *AuthService) Register(ctx context.Context, input api.RegisterInput) (*api.RegisterResult, error) {
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
		return nil, domain.ErrNameRequired
	}
	input.Name = strings.TrimSpace(input.Name)

	existing, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil {
		return nil, fmt.Errorf("register: look up email: %w", err)
	}
	if existing != nil {
		return nil, domain.ErrEmailAlreadyExists
	}

	hash, pepperVersion, err := hashPassword(s.hasher, input.Password)
	if err != nil {
		s.log.Error("failed to hash password", "err", err)
		return nil, domain.ErrInternal
	}

	now := time.Now().UTC()

	user := &domain.User{
		ID:                    uuid.New().String(),
		Email:                 input.Email,
		PasswordHash:          &hash,
		PasswordPepperVersion: pepperVersion,
		Name:                  input.Name,
		Role:                  domain.RoleUser,
		IsBanned:              false,
		TwoFactorEnabled:      s.config.DefaultTwoFactorEnabled,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	// One transaction for the user row and its audit record: a crash between
	// them would otherwise leave a registered account with no record that it
	// was registered. Without an attached manager (mock-built service) this
	// falls back to the previous autocommit shape.
	createUser := func(txCtx context.Context) error {
		if err := s.users.Create(txCtx, user); err != nil {
			if errors.Is(err, port.ErrDuplicateKey) {
				// The GetByEmail check above lost a race — another request
				// created this email between the check and this Create. The
				// unique constraint is the real backstop; this just makes the
				// loser's response match what GetByEmail would have found.
				return domain.ErrEmailAlreadyExists
			}
			s.log.Error("failed to create user", "err", err, "email", input.Email)
			return domain.ErrInternal
		}
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewUserRegisteredEvent(user.ID, net.ParseIP(input.IP), input.UserAgent)); err != nil {
				return err
			}
		}
		return nil
	}

	if s.txManager != nil {
		if err := s.txManager.WithTx(ctx, createUser); err != nil {
			return nil, err
		}
	} else if err := createUser(ctx); err != nil {
		return nil, err
	}

	s.log.Info("user registered", "user_id", user.ID, "email", user.Email)

	if s.config.RequireEmailVerification {
		if _, err := s.verifySvc.SendVerification(ctx, user); err != nil {
			return nil, err
		}
		return &api.RegisterResult{
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
		challenge, aerr := s.twoFactorSvc.challengeWithPassword(ctx, user)
		if aerr != nil {
			return nil, aerr
		}
		return api.NewRegisterResult(api.RegisterResult{
			User:               user,
			RequiresTwoFactor:  true,
			CodeSent:           challenge.Sent,
			TwoFactorChallenge: challenge.ID,
			TwoFactorExpiresAt: challenge.ExpiresAt,
		}, challenge.BindingToken), nil
	}

	sessResult, err := s.createAuditedLoginSession(ctx, user, input.IP, input.UserAgent, nil)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) || errors.Is(err, domain.ErrUserBanned) {
			return nil, err
		}
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	return &api.RegisterResult{
		User:         user,
		Session:      sessResult.Session,
		SessionToken: sessResult.SessionToken,
		RefreshToken: sessResult.RefreshToken,
	}, nil
}

// authenticate resolves and validates email/password credentials.
// On success it returns the authenticated user. requiresVerification is true
// when the user must verify their email before a session can be issued.
func (s *AuthService) authenticate(ctx context.Context, input api.LoginInput) (*domain.User, bool, error) {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	user, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil {
		return nil, false, fmt.Errorf("authenticate: look up email: %w", err)
	}
	if user == nil {
		// Constant-time: a dummy comparison prevents timing-based email
		// enumeration. The registry provides the dummy hash so the burned
		// work matches the configured hasher — a bcrypt dummy under an
		// argon2id deployment would leave the not-found path measurably
		// different from the wrong-password path.
		s.burnDummyPasswordVerification(input.Password)
		return nil, false, domain.ErrInvalidCredentials
	}

	if !user.HasPassword() {
		s.burnDummyPasswordVerification(input.Password)
		return nil, false, domain.ErrInvalidCredentials
	}
	// Preserve the credential snapshot even with a repository returning shared
	// objects; rehash may update this copy only after a successful CAS.
	snapshot := *user
	user = &snapshot

	err = comparePassword(s.hasher, input.Password, *user.PasswordHash, user.PasswordPepperVersion)
	if err != nil {
		// Unknown formats fail closed inside the registry, but the client
		// still gets the same invalid_credentials response as every other
		// failed comparison. Returning a distinct status here would turn a
		// damaged row into an account-enumeration signal.
		if errors.Is(err, registry.ErrUnsupportedHashFormat) {
			s.log.Error("login refused: stored password hash format unrecognized",
				"user_id", user.ID, "hash_prefix", registry.HashFormatPrefix(*user.PasswordHash))
		} else if errors.Is(err, errUnsupportedPepperVersion) {
			s.log.Error("login refused: stored password pepper version unavailable",
				"user_id", user.ID, "pepper_version", *user.PasswordPepperVersion)
		}
		return nil, false, domain.ErrInvalidCredentials
	}

	if user.IsBanned {
		return nil, false, domain.ErrUserBanned
	}

	if s.config.RequireEmailVerification && !user.IsVerified && user.Role != domain.RoleAdmin {
		return user, true, nil
	}

	// Rehash-on-login: the password just verified against an unpeppered
	// legacy row, a legacy algorithm, or stale KDF parameters. Re-hash the
	// just-presented plaintext through the live password pipeline (including
	// the pepper when configured) and current hasher,
	// then persist through one guarded update path. This is the only place a
	// stale hash gets upgraded: no batch migration job, no forced reset. A
	// failure here is logged, never returned — the login itself succeeded,
	// and refusing it over a best-effort upgrade would lock the user out.
	s.rehashIfNeeded(ctx, user, input.Password)

	return user, false, nil
}

// rehashIfNeeded upgrades a verified user's stored hash when its pepper
// version or KDF differs from current. It is
// also the steady-state no-op: current password representation, algorithm,
// and parameters mean no extra hash, no UPDATE, no log noise.
func (s *AuthService) rehashIfNeeded(ctx context.Context, user *domain.User, password string) {
	needsRehash := false
	if pipeline, ok := s.hasher.(versionedPasswordPipeline); ok {
		needsRehash = pipeline.needsRehash(*user.PasswordHash, user.PasswordPepperVersion)
	} else if registry, ok := s.hasher.(rehashRegistry); ok {
		needsRehash = registry.NeedsRehash(*user.PasswordHash)
	}
	if !needsRehash {
		return
	}
	newHash, newPepperVersion, err := hashPassword(s.hasher, password)
	if err != nil {
		s.log.Error("rehash-on-login: failed to rehash password", "err", err, "user_id", user.ID)
		return
	}
	updatedAt := time.Now().UTC()
	updated, err := guardedPasswordUpdate(ctx, s.users, user, newHash, newPepperVersion, updatedAt)
	if err != nil {
		s.log.Error("rehash-on-login: failed to persist rehashed password", "err", err, "user_id", user.ID)
		return
	}
	if !updated {
		// A password reset/change won the race after Compare. Never overwrite
		// the newer credential with a hash of the password just presented.
		s.log.Info("rehash-on-login: skipped because password changed concurrently", "user_id", user.ID)
		return
	}
	s.log.Info("rehash-on-login: password upgraded to current hasher", "user_id", user.ID)
}

// burnDummyPasswordVerification is the single timing-equalization path for
// login attempts that have no stored password to verify. It always delegates
// to the live password pipeline and its current-format probe, so bcrypt and
// Argon2id deployments burn their configured KDF rather than a fixed stand-in.
func (s *AuthService) burnDummyPasswordVerification(password string) {
	_ = s.hasher.Compare(password, s.dummyHashForTiming())
}

// dummyHashForTiming returns a hash in the current hasher's format for the
// no-stored-password timing comparison. Bare hashers (direct service wiring,
// unit tests) get a bcrypt-shaped constant as before.
func (s *AuthService) dummyHashForTiming() string {
	if pipeline, ok := s.hasher.(versionedPasswordPipeline); ok {
		if h := pipeline.dummyHash(); h != "" {
			return h
		}
	}
	if registry, ok := s.hasher.(interface{ DummyHash() string }); ok {
		if h := registry.DummyHash(); h != "" {
			return h
		}
	}
	// Matches the old constant-time path for direct wiring that passes a
	// bare port.Hasher — same shape bcrypt Compare rejects after full work.
	return "$2a$12$....................................................................................................."
}

// rehashRegistry is the facet registry.Registry implements beyond port.Hasher:
// the needsRehash decision and a current-format dummy for timing work.
// AuthService holds port.Hasher (services must be constructible with any
// hasher), so the upgrade path is an interface assertion rather than a field
// type.
type rehashRegistry interface {
	Hash(password string) (string, error)
	Compare(password, hash string) error
	NeedsRehash(stored string) bool
	DummyHash() string
}

// Login authenticates a user.
func (s *AuthService) Login(ctx context.Context, input api.LoginInput) (*api.LoginResult, error) {
	user, requiresVerification, aerr := s.authenticate(ctx, input)
	if aerr != nil {
		if s.audit != nil {
			// The audit failure must not replace the domain error: a failed
			// login has to answer invalid_credentials, not a 500 about
			// audit storage. This is a non-transactional site, so the
			// record autocommits and fail-closed degrades to fail-open
			// (nothing to roll back) — Record cannot fail here in any mode.
			if err := s.audit.Record(ctx, audit.NewLoginFailedEvent(input.Email, net.ParseIP(input.IP), input.UserAgent)); err != nil {
				s.log.Error("login-failed audit record error", "err", err)
			}
		}
		return nil, aerr
	}
	if requiresVerification {
		return &api.LoginResult{
			User:                 user,
			RequiresVerification: true,
		}, nil
	}

	// Ordering: banned → email-verify → password → 2FA → session.
	if s.enforceTwoFactor(user) {
		challenge, aerr := s.twoFactorSvc.challengeWithPassword(ctx, user)
		if aerr != nil {
			return nil, aerr
		}
		return api.NewLoginResult(api.LoginResult{
			User:               user,
			RequiresTwoFactor:  true,
			CodeSent:           challenge.Sent,
			TwoFactorChallenge: challenge.ID,
			TwoFactorExpiresAt: challenge.ExpiresAt,
		}, challenge.BindingToken), nil
	}

	sessResult, err := s.createAuditedLoginSession(ctx, user, input.IP, input.UserAgent, func(sessionID string) audit.Event {
		return audit.NewLoginEvent(user.ID, sessionID, net.ParseIP(input.IP), input.UserAgent, true)
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) || errors.Is(err, domain.ErrUserBanned) {
			return nil, err
		}
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	if err := s.users.UpdateLastLoginAt(ctx, user.ID, time.Now().UTC()); err != nil {
		s.log.Error("failed to update last login time", "err", err, "user_id", user.ID)
	}

	s.log.Info("user logged in", "user_id", user.ID, "ip", input.IP)

	return &api.LoginResult{
		User:         user,
		Session:      sessResult.Session,
		SessionToken: sessResult.SessionToken,
		RefreshToken: sessResult.RefreshToken,
	}, nil
}

// AdminLogin authenticates a user and requires the admin role.
// Non-admin users are rejected with generic invalid_credentials so the
// endpoint never reveals whether an account is an admin.
func (s *AuthService) AdminLogin(ctx context.Context, input api.LoginInput) (*api.LoginResult, error) {
	user, requiresVerification, aerr := s.authenticate(ctx, input)
	if aerr != nil {
		if s.audit != nil {
			// Non-transactional site: the domain error wins, and fail-closed
			// degrades to fail-open (nothing to roll back).
			if err := s.audit.Record(ctx, audit.NewAdminLoginFailedEvent(input.Email, net.ParseIP(input.IP), input.UserAgent)); err != nil {
				s.log.Error("admin login-failed audit record error", "err", err)
			}
		}
		return nil, aerr
	}

	if requiresVerification || user.Role != domain.RoleAdmin {
		if s.audit != nil {
			if err := s.audit.Record(ctx, audit.NewAdminLoginFailedEvent(input.Email, net.ParseIP(input.IP), input.UserAgent)); err != nil {
				s.log.Error("admin login-failed audit record error", "err", err)
			}
		}
		return nil, domain.ErrInvalidCredentials
	}

	// Apply the same account policy used by ordinary login. An explicit admin
	// opt-out does not bypass a global or per-user second-factor requirement.
	if s.enforceTwoFactor(user) {
		challenge, aerr := s.twoFactorSvc.challengeWithPassword(ctx, user)
		if aerr != nil {
			return nil, aerr
		}
		return api.NewLoginResult(api.LoginResult{
			User:               user,
			RequiresTwoFactor:  true,
			CodeSent:           challenge.Sent,
			TwoFactorChallenge: challenge.ID,
			TwoFactorExpiresAt: challenge.ExpiresAt,
		}, challenge.BindingToken), nil
	}

	sessResult, err := s.createAuditedLoginSession(ctx, user, input.IP, input.UserAgent, func(sessionID string) audit.Event {
		return audit.NewAdminLoginSuccessEvent(user.ID, sessionID, net.ParseIP(input.IP), input.UserAgent)
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) || errors.Is(err, domain.ErrUserBanned) {
			return nil, err
		}
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	if err := s.users.UpdateLastLoginAt(ctx, user.ID, time.Now().UTC()); err != nil {
		s.log.Error("failed to update last login time", "err", err, "user_id", user.ID)
	}

	s.log.Info("admin logged in", "user_id", user.ID, "ip", input.IP)

	return &api.LoginResult{
		User:         user,
		Session:      sessResult.Session,
		SessionToken: sessResult.SessionToken,
		RefreshToken: sessResult.RefreshToken,
	}, nil
}

// ValidateSession validates a session token and returns its user and session.
func (s *AuthService) ValidateSession(ctx context.Context, tokenRaw string) (*domain.User, *domain.Session, error) {
	session, err := s.sessionSvc.Validate(ctx, tokenRaw)
	if err != nil {
		if isSessionValidationRejection(err) {
			return nil, nil, domain.ErrSessionExpired
		}
		return nil, nil, fmt.Errorf("validate session: %w", err)
	}

	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("validate session: lookup: %w", err)
	}
	if user == nil {
		return nil, nil, domain.ErrSessionExpired
	}
	if user.IsBanned {
		return nil, nil, domain.ErrUserBanned
	}

	return user, session, nil
}

func isSessionValidationRejection(err error) bool {
	return errors.Is(err, domain.ErrSessionNotFound) ||
		errors.Is(err, domain.ErrSessionExpired) ||
		errors.Is(err, domain.ErrSessionRevoked) ||
		errors.Is(err, domain.ErrMaxLifetimeExceeded)
}

// Logout ends a session.
func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	err := s.withTx(ctx, func(txCtx context.Context) error {
		if err := s.sessionSvc.RevokeByID(txCtx, sessionID); err != nil {
			return err
		}
		if s.audit != nil {
			return s.audit.Record(txCtx, audit.NewLogoutEvent("", sessionID, nil, ""))
		}
		return nil
	})
	if err != nil {
		s.log.Error("failed to revoke session", "err", err, "session_id", sessionID)
		return domain.ErrInternal
	}
	return nil
}

// ChangeName changes a user's display name.
func (s *AuthService) ChangeName(ctx context.Context, userID, newName string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("change name: lookup: %w", err)
	}
	if user == nil {
		return domain.ErrUserNotFound
	}
	if newName == "" {
		return domain.NewError("validation_error", "Name cannot be empty")
	}
	if err := updateUserName(ctx, s.users, user, newName, time.Now().UTC()); err != nil {
		s.log.Error("failed to update name", "err", err, "user_id", userID)
		return domain.ErrInternal
	}
	s.log.Info("name changed", "user_id", userID)
	if s.audit != nil {
		if err := s.audit.Record(ctx, audit.NewNameChangedEvent(userID)); err != nil {
			return err
		}
	}
	return nil
}

// DeleteAccount deletes a user's account after password verification.
func (s *AuthService) DeleteAccount(ctx context.Context, userID string, password string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("delete account: lookup: %w", err)
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	if !user.HasPassword() {
		return domain.ErrPasswordRequired
	}
	if err := comparePassword(s.hasher, password, *user.PasswordHash, user.PasswordPepperVersion); err != nil {
		return domain.NewError("wrong_password", "Password is incorrect")
	}

	// Account deletion requires the coordinator: one transaction unwinding
	// org memberships with counter upkeep, session revocation, and the
	// last-usable-admin guard. The library wiring always attaches it; a
	// nil coordinator means a miswired service, which fails closed.
	if s.deletion == nil {
		s.log.Error("account deletion refused: no deletion coordinator attached", "user_id", userID)
		return domain.ErrInternal
	}
	record := func(txCtx context.Context) error {
		if s.audit == nil {
			return nil
		}
		return s.audit.Record(txCtx, audit.NewAccountDeletedEvent(userID))
	}
	if err := s.deletion.DeleteUserAndRecord(ctx, userID, record); err != nil {
		s.log.Error("failed to delete account", "err", err, "user_id", userID)
		return err
	}
	s.log.Info("account deleted", "user_id", userID)
	return nil
}

// RequestDeleteAccount sends an account-deletion code.
func (s *AuthService) RequestDeleteAccount(ctx context.Context, userID string) error {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("request delete account: lookup: %w", err)
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	if user.HasPassword() {
		return domain.NewError("password_account", "Use DELETE /auth/account with password to delete your account")
	}

	if s.mailer == nil {
		return domain.ErrEmailNotConfigured
	}

	hasValid, err := s.tokens.HasValidByUserAndType(ctx, userID, domain.TokenDeleteAccount)
	if err != nil {
		return fmt.Errorf("request delete account: check outstanding code: %w", err)
	}
	if hasValid {
		// A live but rotation-stale code can never verify — confirming it
		// could only answer expired. Don't report "already sent" for it;
		// clear it and fall through to mint a fresh code instead.
		last, lerr := s.tokens.GetLastByUserAndType(ctx, userID, domain.TokenDeleteAccount)
		if lerr != nil {
			return fmt.Errorf("request delete account: look up outstanding code: %w", lerr)
		}
		if last == nil || last.UsedAt != nil ||
			time.Now().UTC().After(last.ExpiresAt) ||
			!stalePepper(last.CreatedAt, s.config.PepperRotatedAt) {
			return nil
		}
		if derr := s.tokens.DeleteUnusedByUserAndType(ctx, userID, domain.TokenDeleteAccount); derr != nil {
			s.log.Error("failed to clear rotation-stale deletion token", "err", derr, "user_id", userID)
			return domain.ErrInternal
		}
	}

	raw, err := otp.Generate(8)
	if err != nil {
		s.log.Error("failed to generate deletion code", "err", err, "user_id", userID)
		return domain.ErrInternal
	}

	if len(s.config.OTPPepper) == 0 {
		s.log.Error("delete-account request refused: no OTP pepper derived — refusing")
		return domain.ErrInternal
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashOTP(raw, s.config.OTPPepper),
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

// ConfirmDeleteAccount deletes an account using a valid code.
func (s *AuthService) ConfirmDeleteAccount(ctx context.Context, input api.ConfirmDeleteAccountInput) error {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil {
		return fmt.Errorf("confirm delete account: lookup: %w", err)
	}
	if user == nil {
		return domain.ErrUserNotFound
	}

	// The deletion code is an 8-char OTP (~40 bits): low-entropy, stored as
	// HMAC-SHA256(OTPPepper, code). The request carries the user ID, so the
	// candidate is fetched by user+type and compared here in app code with
	// hmac.Equal (verifyOTP) — never a SQL `=` lookup over the MAC, never
	// bcrypt.
	if len(s.config.OTPPepper) == 0 {
		s.log.Error("delete-account confirm refused: no OTP pepper derived — refusing")
		return domain.ErrInternal
	}
	token, err := s.tokens.GetLastByUserAndType(ctx, input.UserID, domain.TokenDeleteAccount)
	if err != nil {
		return fmt.Errorf("confirm delete account: lookup: %w", err)
	}
	if token == nil {
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

	// A rotation-stale code predates the live pepper and can never verify.
	// Answer expired (request a new code, don't retry) without running the
	// HMAC — the old pepper is gone, so the outcome is unknowable either way.
	if stalePepper(token.CreatedAt, s.config.PepperRotatedAt) {
		return domain.ErrDeleteCodeExpired
	}

	if !verifyOTP(input.Code, token.TokenHash, s.config.OTPPepper) {
		return domain.ErrDeleteCodeInvalid
	}

	if token.UserID == nil || *token.UserID != input.UserID {
		return domain.ErrDeleteCodeInvalid
	}

	// Claim the validated code and delete atomically. Do not write the token
	// after commit: foreign-key cascades may already have removed its row.
	if s.deletion == nil {
		s.log.Error("account deletion via code refused: no deletion coordinator attached", "user_id", input.UserID)
		return domain.ErrInternal
	}
	record := func(txCtx context.Context) error {
		if s.audit == nil {
			return nil
		}
		return s.audit.Record(txCtx, audit.NewAccountDeletedEvent(input.UserID))
	}
	if err := s.deletion.deleteWithCode(ctx, input.UserID, s.tokens, token, record); err != nil {
		s.log.Error("failed to delete account via code", "err", err, "user_id", input.UserID)
		var authErr *domain.AuthError
		if errors.As(err, &authErr) {
			return err
		}
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
