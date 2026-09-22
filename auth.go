package goauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/hasher/registry"
	"github.com/nazimdjebloun/go-auth/internal/crypto"
	"github.com/nazimdjebloun/go-auth/internal/handler"
	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/nazimdjebloun/go-auth/token"
)

type Auth struct {
	cfg      Config
	pool     *pgxpool.Pool
	db       *sqlstore.DB
	Services Services
	Handlers HandlerGroup

	// cookies is the resolved session/refresh cookie scope, built once in
	// New() via cookiesFromSession. Facade helpers and all wiring read it —
	// nothing pulls cookie names off the session service at request time.
	cookies middleware.CookieSettings

	authMW      func(http.Handler) http.Handler
	adminMW     func(http.Handler) http.Handler
	rateLimitMW func(http.Handler) http.Handler
	corsMW      func(http.Handler) http.Handler
	orgMemberMW func(http.Handler) http.Handler

	authService      *service.AuthService
	passwordService  *service.PasswordService
	sessionService   *service.SessionService
	verifyService    *service.VerificationService
	inviteService    *service.InviteService
	adminService     *service.AdminService
	oAuthService     *service.OAuthService
	orgService       *service.OrgService
	orgInviteService *service.OrgInviteService
	auditService     *audit.AuditService
	auditLogRepo     port.AuditLogRepository

	// twoFactorStore is always library-constructed (see New), so unlike the
	// rate-limit Store it is unconditionally ours to close.
	twoFactorStore ratelimit.Store
	maintenance    *maintenanceRunner
}

type Services struct {
	Auth      *AuthService
	Password  *PasswordService
	Session   *SessionService
	Verify    *VerificationService
	Invite    *InviteService
	Admin     *AdminService
	OAuth     *OAuthService
	Org       *OrgService
	OrgInvite *OrgInviteService
	TwoFactor *TwoFactorService
	AuditLog  port.AuditLogRepository
}

// New builds the Auth instance from a config produced by NewConfig(opts...)
// — the only supported way to configure go-auth. NewConfig is what runs
// validate() (required fields, secret length, origin policy, rate-limit
// settings, and everything else in config.validate()); Config's fields are
// unexported, so NewConfig is the only way to build one New() accepts.
// The validated check below is belt-and-suspenders defense in depth against
// silently proceeding with unvalidated — and in the case of an empty
// secret, cryptographically unsafe — settings.
const startupDatabaseTimeout = 10 * time.Second

func New(in *Config) (*Auth, error) {
	if in == nil {
		return nil, fmt.Errorf("goauth: nil config — build one with goauth.NewConfig(goauth.WithApp(...), ...)")
	}
	// Work on a deep copy: New resolves defaults onto the config it is given
	// (CSRF cookie scope, database.opened, rate-limit logger), and a caller
	// reusing one Config for two Auth instances must not see the first one's
	// resolutions. clone shares only live objects the consumer owns.
	cfg := in.clone()
	if !cfg.resolved.validated {
		return nil, fmt.Errorf(
			"goauth: config was not built via NewConfig(opts...) — " +
				"construct it with goauth.NewConfig(goauth.WithApp(...), ...) so " +
				"required fields and security settings are validated",
		)
	}
	// Option is an exported function type, so a caller can technically apply
	// one to an already validated Config. Recheck password-pepper material at
	// the construction boundary: an empty environment value must stop startup,
	// never derive a predictable key or silently disable peppering.
	if err := cfg.validatePasswordPepper(); err != nil {
		return nil, fmt.Errorf("goauth: invalid password pepper configuration: %w", err)
	}
	if cfg.app.Environment.normalize() == EnvironmentDev && cfg.logger != nil {
		cfg.logger.Warn("goauth: running in dev environment", "cookie_secure", cfg.resolved.cookieSecure)
	}

	// Derive the core cryptographic keys from the application root secret.
	// The optional password pepper uses independent input below.
	keys := keyring.Derive([]byte(cfg.secret))

	applyCSRFTokenDefaults(&cfg, keys)

	// New password hashes use either the configured implementation or the
	// historical bcrypt default. Verification always goes through the registry
	// so stored hashes select their verifier by prefix. The legacy bcrypt
	// verifier stays at cost 12: Compare reads cost from the stored hash, and
	// using a caller's WithBcryptCost value here would only make the startup
	// probe needlessly expensive when a custom current hasher is active.
	const defaultBcryptCost = 12
	currentHasher := cfg.passwordHasher
	if currentHasher == nil {
		cost := defaultBcryptCost
		if cfg.bcryptCost > 0 {
			cost = cfg.bcryptCost
		}
		currentHasher = hasher.New(cost)
	}
	passwordRegistry, err := registry.New(currentHasher, hasher.New(defaultBcryptCost))
	if err != nil {
		return nil, fmt.Errorf("goauth: building password hasher registry: %w", err)
	}
	// Derive each independently managed pepper secret with the password-only
	// purpose string. The version is persisted beside the hash and selects one
	// exact key during verification; no request searches the keyring.
	passwordPepperKeys := make(map[uint32][]byte, len(cfg.passwordPepper.Keys))
	for version, secret := range cfg.passwordPepper.Keys {
		passwordPepperKeys[version] = keyring.DerivePasswordPepper([]byte(secret))
	}
	passwordHasher, err := service.NewPasswordHasher(passwordRegistry, cfg.passwordPepper.CurrentVersion, passwordPepperKeys)
	if err != nil {
		return nil, fmt.Errorf("goauth: building password hasher: %w", err)
	}
	var hasherImpl port.Hasher = passwordHasher

	if err := requireDriverSupport(&cfg); err != nil {
		return nil, err
	}

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), startupDatabaseTimeout)
	defer cancelStartup()
	pool, sqlDB, err := openDatabase(startupCtx, &cfg)
	if err != nil {
		return nil, err
	}
	constructed := false
	defer func() {
		if !constructed && cfg.app.Database.opened && sqlDB != nil {
			_ = sqlDB.Close()
		}
	}()
	sessionRepo := sqlstore.NewSessionRepository(sqlDB)
	if cfg.logger != nil {
		sessionRepo.WithLogger(cfg.logger)
	}

	userRepo := sqlstore.NewUserRepository(sqlDB)
	// Keep the zero-config path lazy: historically New with a borrowed pgx
	// pool did not dial it. Once any pepper key is configured, validate every
	// version present in the database before serving requests. Omitting the
	// option against an already-peppered database still fails closed per-row at
	// login; it never falls back to treating a peppered hash as unpeppered.
	if len(passwordPepperKeys) > 0 {
		storedPepperVersions, err := userRepo.ListPasswordPepperVersions(startupCtx)
		if err != nil {
			return nil, fmt.Errorf("goauth: validating stored password pepper versions: %w", err)
		}
		if err := passwordHasher.ValidateStoredVersions(storedPepperVersions); err != nil {
			return nil, fmt.Errorf("goauth: invalid password pepper configuration: %w", err)
		}
	}
	tokenRepo := sqlstore.NewTokenRepository(sqlDB)
	inviteRepo := sqlstore.NewInviteRepository(sqlDB)
	providerAccountRepo := sqlstore.NewProviderAccountRepository(sqlDB)
	if keys.OAuthEnc != nil {
		enc, err := crypto.NewEncryptor(keys.OAuthEnc)
		if err != nil {
			return nil, fmt.Errorf("goauth: oauth encryptor: %w", err)
		}
		providerAccountRepo.WithDecryptor(enc.Decrypt)
	}
	auditLogRepo := sqlstore.NewAuditLogRepository(sqlDB)

	genImpl := token.New()

	mailer, err := resolveMailer(&cfg)
	if err != nil {
		return nil, err
	}

	templateProvider, urlValidator, err := resolveTemplates(&cfg)
	if err != nil {
		return nil, err
	}

	oauthProviders, err := collectOAuthProviders(&cfg)
	if err != nil {
		return nil, err
	}

	auditSvc, auditPub, err := startAuditService(&cfg, sqlDB)
	if err != nil {
		return nil, err
	}

	commonCfg := service.CommonConfig{
		AppName:    cfg.app.Name,
		BaseURL:    cfg.app.BaseURL,
		SessionTTL: cfg.session.TTL,
		TokenTTL:   cfg.session.TokenTTL,
		Logger:     cfg.logger,
		Audit:      auditPub,
	}

	serviceCfg := service.Config{
		CommonConfig:               commonCfg,
		InviteOnly:                 !cfg.registration.AllowPublic,
		EnableEmailPassword:        cfg.registration.EnableEmailPassword,
		EnableOAuth:                cfg.registration.EnableOAuth,
		EnableInvite:               cfg.registration.EnableInvite,
		RequireEmailVerification:   cfg.registration.RequireEmailVerification,
		InviteTTL:                  cfg.registration.InviteTTL,
		VerificationCodeTTL:        cfg.registration.VerificationCodeTTL,
		VerificationResendInterval: cfg.registration.VerificationResendInterval,
		PasswordPolicy:             cfg.security.PasswordPolicy,
		TemplateProvider:           templateProvider,
		URLValidator:               urlValidator,

		RequireEmail2FA:                  cfg.twoFactor.RequireEmail2FA,
		DefaultTwoFactorEnabled:          cfg.twoFactor.DefaultEnabled,
		TwoFactorCodeTTL:                 cfg.twoFactor.CodeTTL,
		TwoFactorBindingKey:              keys.TwoFactor,
		OTPPepper:                        keys.OTPPepper,
		PepperRotatedAt:                  cfg.security.PepperRotatedAt,
		DisableTwoFactorChallengeBinding: cfg.twoFactor.DisableChallengeBinding,
		TwoFactorChallengeCookieName:     cfg.twoFactor.ChallengeCookieName,
		DisableAdminTwoFactor:            cfg.twoFactor.DisableAdminTwoFactor,
	}

	sessionCfg := buildSessionConfig(&cfg, auditPub)
	cookies := cookiesFromSession(sessionCfg)

	sessSvc := service.NewSessionService(sessionRepo, genImpl, sessionCfg)
	// Direct session API calls must get the same record-iff-commit guarantee
	// as login: the session mutation and its audit record share one tx.
	sessSvc.AttachTxManager(sqlDB)

	verifySvc := service.NewVerificationService(userRepo, tokenRepo, genImpl, mailer, sqlDB, serviceCfg)

	// The 2FA failure counter gets its own store, deliberately not the
	// rate-limit one.
	//
	// The rate-limit store evicts under pressure — that is what keeps it
	// bounded — and an evicted 2FA counter is a suspicious-activity email
	// that silently never sends, which is exactly the outcome someone
	// grinding second-factor codes wants. Sharing the store would also mean
	// any Redis backend a consumer swaps in has to be reachable for a
	// notification that was never allowed to block a login.
	//
	// Eviction is off here because the key space is closed: one key per
	// account with a 2FA failure in the last hour, keyed by a user ID read
	// from the database, not by anything a caller supplies.
	twoFactorStore := ratelimit.NewMemoryStore(
		ratelimit.WithoutEviction(),
		ratelimit.WithStoreLogger(cfg.logger),
	)
	twoFactorSvc := service.NewTwoFactorService(userRepo, sessionRepo, tokenRepo, hasherImpl, mailer, twoFactorStore, serviceCfg, sessSvc)

	authSvc := service.NewAuthService(userRepo, sessionRepo, tokenRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc, verifySvc, twoFactorSvc)
	// Register commits the user row and its audit record in one
	// transaction, so a crash cannot leave an account with no record of its
	// registration (record-iff-commit).
	authSvc.AttachTxManager(sqlDB)
	passSvc := service.NewPasswordService(userRepo, tokenRepo, hasherImpl, genImpl, mailer, sessionRepo, sqlDB, serviceCfg)
	inviteSvc := service.NewInviteService(userRepo, sessionRepo, inviteRepo, hasherImpl, genImpl, mailer, sqlDB, serviceCfg, sessSvc, twoFactorSvc)
	adminSvc := service.NewAdminService(userRepo, sessionRepo, providerAccountRepo, auditLogRepo, hasherImpl, serviceCfg, sessSvc)

	var oauthSvc *service.OAuthService
	if len(oauthProviders) > 0 {
		var encryptor *crypto.Encryptor
		if keys.OAuthEnc != nil {
			encryptor, err = crypto.NewEncryptor(keys.OAuthEnc)
			if err != nil {
				return nil, fmt.Errorf("goauth: oauth encryptor: %w", err)
			}
		}
		oauthCfg := service.OAuthServiceConfig{
			CommonConfig:             commonCfg,
			RequireEmailVerification: cfg.registration.RequireEmailVerification,
			EnableOAuth:              cfg.registration.EnableOAuth,
			InviteOnly:               !cfg.registration.AllowPublic,
			Encryptor:                encryptor,
		}
		oauthSvc = service.NewOAuthService(oauthProviders, providerAccountRepo, userRepo, tokenRepo, hasherImpl, genImpl, sessSvc, verifySvc, sqlDB, oauthCfg)
	}

	var orgSvc *service.OrgService
	var orgInviteSvc *service.OrgInviteService
	var orgRepo port.OrgRepository
	if cfg.organizations.Enable {
		orgRepo = sqlstore.NewOrgRepository(sqlDB)
		orgInviteRepo := sqlstore.NewOrgInviteRepository(sqlDB)
		orgSvc = service.NewOrgService(orgRepo, userRepo, sessionRepo, sqlDB, service.OrgServiceConfig{
			MaxOrgsPerUser: cfg.organizations.MaxOrgsPerUser,
			Logger:         cfg.logger,
			Audit:          auditPub,
		})
		orgInviteSvc = service.NewOrgInviteService(orgInviteRepo, orgRepo, userRepo, sqlDB, genImpl, mailer, service.OrgInviteServiceConfig{
			MaxOrgsPerUser:   cfg.organizations.MaxOrgsPerUser,
			InviteTTL:        cfg.organizations.InviteTTL,
			BaseURL:          cfg.app.BaseURL,
			AppName:          cfg.app.Name,
			TemplateProvider: templateProvider,
			URLValidator:     urlValidator,
			Logger:           cfg.logger,
			Audit:            auditPub,
		})
	}

	// One shared account-deletion coordinator for both services: every
	// deletion path (admin, password-confirmed, code-confirmed) runs the
	// same transactional invariants — org counter upkeep, session
	// revocation, last-usable-admin guard. orgRepo is nil when
	// organizations are disabled, and the coordinator skips membership
	// upkeep in that case.
	accountDeletion := service.NewAccountDeletion(sqlDB, sqlstore.NewOrgRepository(sqlDB), sessionRepo, userRepo)
	authSvc.AttachAccountDeletion(accountDeletion)
	adminSvc.AttachAccountDeletion(accountDeletion)

	// One description of the deployment's proxy setup, shared by everything
	// that has to reason about it: the rate limiter keys limits on it, the
	// CSRF origin check recovers the original scheme/host with it, and the
	// handlers below record it on sessions and audit events. Nil rateLimit
	// leaves it zero, which trusts no forwarding header at all.
	var clientIPCfg middleware.ClientIPConfig
	if cfg.rateLimit != nil {
		clientIPCfg = middleware.ClientIPConfig{
			Header:     cfg.rateLimit.IPAddressHeader,
			TrustedIPs: cfg.rateLimit.TrustedIPs,
		}
	}

	h := handler.NewWithLogger(handler.Deps{
		Auth:      authSvc,
		Password:  passSvc,
		Session:   sessSvc,
		Verify:    verifySvc,
		Invite:    inviteSvc,
		Admin:     adminSvc,
		OAuth:     oauthSvc,
		Org:       orgSvc,
		OrgInvite: orgInviteSvc,
		TwoFactor: twoFactorSvc,
		AuditLog:  auditLogRepo,
	}, cfg.logger, cfg.security.CSRFToken, clientIPCfg, cookies)

	// OAuth handlers (separate because they need baseURL for redirects).
	oauthHandlers := handler.NewOAuthHandlers(oauthSvc, cfg.app.BaseURL, cfg.security.CSRFToken, clientIPCfg, cookies, cfg.logger)

	authMW := middleware.AuthMiddleware(sessSvc, cookies, userRepo, cfg.logger)
	adminMW := middleware.RequireRole(domain.RoleAdmin, cfg.logger)
	var trustedIPs []string
	if cfg.rateLimit != nil {
		cfg.rateLimit.Logger = cfg.logger
		trustedIPs = cfg.rateLimit.TrustedIPs
		if !cfg.rateLimit.Enabled && cfg.logger != nil {
			cfg.logger.Warn("goauth: rate limiting is disabled — this is insecure for production",
				"fix", "re-enable with WithRateLimitEnabled(true) or use a trusted edge rate limiter")
		}
		if cfg.rateLimit.Enabled && cfg.logger != nil && ratelimit.IsDefaultStore(cfg.rateLimit.Store) {
			// Heuristic reminder, not a diagnosis — the library has no way to
			// detect "multiple instances" directly, so this fires on every
			// process using the default store, dev included.
			cfg.logger.Warn("goauth: rate limiting is using the default in-memory store, which does not share state across instances",
				"fix", "if you run more than one instance behind a load balancer, use WithRateLimitStore with a shared store (e.g. Redis) or limits apply per-instance rather than globally")
		}
	}
	rateLimitMW := middleware.RateLimit(cfg.rateLimit)
	csrfMW := middleware.OriginCheck(cfg.security.AllowedOrigins, cfg.security.AllowMissingCSRFHeaders, trustedIPs, cfg.logger)
	csrfTokenMW := middleware.CSRFToken(cfg.security.CSRFToken)
	corsMW := middleware.CORS(cfg.security.AllowedOrigins)

	// Org authorization: orgMemberMW verifies the authenticated user is a
	// member of the {orgID} path segment; orgAdminMW/orgOwnerMW additionally
	// require a minimum role. Must run after authMW (needs the user in
	// context) and before the handler. Safe to construct even when
	// organizations are disabled (orgRepo is nil) — the routes that use these
	// are only registered by Mount when a.orgService != nil, so the
	// underlying orgs.GetMembership call is never reached.
	orgUserID := func(ctx context.Context) string {
		if u := middleware.GetUserFromContext(ctx); u != nil {
			return u.ID
		}
		return ""
	}
	orgMemberMW := middleware.RequireOrgMember(orgRepo, orgUserID)
	orgAdminMW := middleware.RequireOrgRole(domain.OrgRoleAdmin)
	orgOwnerMW := middleware.RequireOrgRole(domain.OrgRoleOwner)

	maintenance := newMaintenanceRunner(cfg.maintenance, collectMaintenanceTargets(sessionRepo, tokenRepo))
	if !cfg.maintenance.Disable {
		maintenance.start()
	}

	constructed = true
	return &Auth{
		cfg:              cfg,
		pool:             pool,
		db:               sqlDB,
		cookies:          cookies,
		authMW:           authMW,
		adminMW:          adminMW,
		rateLimitMW:      rateLimitMW,
		corsMW:           corsMW,
		orgMemberMW:      orgMemberMW,
		authService:      authSvc,
		passwordService:  passSvc,
		sessionService:   sessSvc,
		verifyService:    verifySvc,
		inviteService:    inviteSvc,
		adminService:     adminSvc,
		oAuthService:     oauthSvc,
		orgService:       orgSvc,
		orgInviteService: orgInviteSvc,
		auditService:     auditSvc,
		auditLogRepo:     auditLogRepo,
		twoFactorStore:   twoFactorStore,
		maintenance:      maintenance,
		Services: Services{
			Auth:      authSvc,
			Password:  passSvc,
			Session:   sessSvc,
			Verify:    verifySvc,
			Invite:    inviteSvc,
			Admin:     adminSvc,
			OAuth:     oauthSvc,
			Org:       orgSvc,
			OrgInvite: orgInviteSvc,
			TwoFactor: twoFactorSvc,
			AuditLog:  auditLogRepo,
		},
		Handlers: HandlerGroup{
			// Public auth endpoints: CORS outer, then rate limit, then CSRF token + origin check.
			// CORS is outermost so preflight OPTIONS short-circuits before rate-limit accounting.
			Register:                 corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.Register))))).ServeHTTP,
			Login:                    corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.Login))))).ServeHTTP,
			AdminLogin:               corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.AdminLogin))))).ServeHTTP,
			Logout:                   corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.Logout))))).ServeHTTP,
			ForgotPassword:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.ForgotPassword))))).ServeHTTP,
			ResetPassword:            corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.ResetPassword))))).ServeHTTP,
			ChangePassword:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ChangePassword)))))).ServeHTTP,
			SetPasswordRequest:       corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.SetPasswordRequest)))))).ServeHTTP,
			SetPasswordConfirm:       corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.SetPasswordConfirm))))).ServeHTTP,
			VerifyEmail:              corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.VerifyEmail))))).ServeHTTP,
			ResendVerification:       corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ResendVerification)))))).ServeHTTP,
			ResendVerificationPublic: corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.ResendVerificationPublic))))).ServeHTTP,
			ListSessions:             corsMW(authMW(http.HandlerFunc(h.ListSessions))).ServeHTTP,
			GetAllSessions:           corsMW(authMW(http.HandlerFunc(h.GetAllSessions))).ServeHTTP,
			RevokeSession:            corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RevokeSession))))).ServeHTTP,
			RevokeManySessions:       corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RevokeManySessions))))).ServeHTTP,
			RevokeAllSessions:        corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RevokeAllSessions))))).ServeHTTP,
			InviteRegister:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.InviteRegister))))).ServeHTTP,
			// VerifyTwoFactor/ResendTwoFactor are public — they complete a login
			// already in progress, not an authenticated action — but rate-limited
			// and CSRF-checked like Login/Register.
			VerifyTwoFactor: corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.VerifyTwoFactor))))).ServeHTTP,
			ResendTwoFactor: corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.ResendTwoFactor))))).ServeHTTP,
			Enable2FA:       corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.Enable2FA)))))).ServeHTTP,
			Disable2FA:      corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.Disable2FA)))))).ServeHTTP,
			GetInviteInfo:   corsMW(rateLimitMW(http.HandlerFunc(h.GetInviteInfo))).ServeHTTP,
			// Rate-limited like every other authenticated read: a junk cookie
			// named like a session still costs a session lookup here.
			GetMe:                corsMW(rateLimitMW(authMW(http.HandlerFunc(h.GetMe)))).ServeHTTP,
			RefreshToken:         corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.RefreshToken))))).ServeHTTP,
			ChangeName:           corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ChangeName))))).ServeHTTP,
			DeleteAccount:        corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.DeleteAccount)))))).ServeHTTP,
			RequestDeleteAccount: corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RequestDeleteAccount)))))).ServeHTTP,
			// Confirm delete requires an authenticated session (user ID from context only).
			ConfirmDeleteAccount: corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ConfirmDeleteAccount)))))).ServeHTTP,
			// Admin endpoints: CORS outer, then rate limit, then auth + admin role check.
			ListUsers:              corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.ListUsers))))).ServeHTTP,
			CountUsers:             corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.CountUsers))))).ServeHTTP,
			GetUserDetail:          corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.GetUserDetail))))).ServeHTTP,
			UpdateUserRole:         corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.UpdateUserRole))))))).ServeHTTP,
			BanUser:                corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BanUser))))))).ServeHTTP,
			UnbanUser:              corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.UnbanUser))))))).ServeHTTP,
			DeleteUser:             corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.DeleteUser))))))).ServeHTTP,
			RevokeUserSessions:     corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.RevokeUserSessions))))))).ServeHTTP,
			AdminCreateUser:        corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminCreateUser))))))).ServeHTTP,
			AdminListUserSessions:  corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListUserSessions))))).ServeHTTP,
			AdminRevokeUserSession: corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminRevokeUserSession))))))).ServeHTTP,
			AdminListAuditLogs:     corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListAuditLogs))))).ServeHTTP,
			AdminListUserAuditLogs: corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListUserAuditLogs))))).ServeHTTP,
			AdminStats:             corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.GetAdminStats))))).ServeHTTP,
			AdminRegistrationTrend: corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.GetRegistrationTrend))))).ServeHTTP,
			AdminLoginActivity:     corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.GetLoginActivity))))).ServeHTTP,
			AdminListSessions:      corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListSessions))))).ServeHTTP,
			BulkBanUsers:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkBanUsers))))))).ServeHTTP,
			BulkUnbanUsers:         corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkUnbanUsers))))))).ServeHTTP,
			BulkDeleteUsers:        corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkDeleteUsers))))))).ServeHTTP,
			BulkRevokeUserSessions: corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkRevokeUserSessions))))))).ServeHTTP,
			CreateInvite:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.CreateInvite))))))).ServeHTTP,
			ListInvites:            corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.ListInvites))))).ServeHTTP,
			CountInvites:           corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.CountInvites))))).ServeHTTP,
			RevokeInvite:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.RevokeInvite))))))).ServeHTTP,
			ResendInvite:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.ResendInvite))))))).ServeHTTP,
			HardDeleteInvite:       corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.HardDeleteInvite))))))).ServeHTTP,
			BulkSendInvites:        corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkSendInvites))))))).ServeHTTP,
			BulkResendInvites:      corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkResendInvites))))))).ServeHTTP,
			BulkRevokeInvites:      corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkRevokeInvites))))))).ServeHTTP,
			BulkDeleteInvites:      corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkDeleteInvites))))))).ServeHTTP,
			OAuthInitiate:          corsMW(http.HandlerFunc(oauthHandlers.Initiate)).ServeHTTP,
			OAuthCallback:          corsMW(http.HandlerFunc(oauthHandlers.Callback)).ServeHTTP,
			OAuthLink:              corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(oauthHandlers.InitiateLink))))).ServeHTTP,
			OAuthUnlink:            corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(oauthHandlers.Unlink))))).ServeHTTP,
			OAuthProviders:         corsMW(authMW(http.HandlerFunc(oauthHandlers.ListConnected))).ServeHTTP,
			CSRFToken:              corsMW(csrfTokenMW(http.HandlerFunc(h.GetCSRFToken))).ServeHTTP,
			// Org routes: authMW authenticates, then orgMemberMW/orgAdminMW/
			// orgOwnerMW enforce membership and minimum role per the access
			// levels documented in docs/guides/organizations.mdx.
			// CreateOrg/ListUserOrgs/
			// AcceptOrgInvite/SetActiveOrg/ClearActiveOrg have no {orgID}
			// path segment (self-service or org resolved from a code/body),
			// so they stay authMW-only; SetActiveOrg/AcceptInvite already
			// check membership inside the service layer.
			CreateOrg:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.CreateOrg)))))).ServeHTTP,
			GetOrg:              corsMW(rateLimitMW(authMW(orgMemberMW(http.HandlerFunc(h.GetOrg))))).ServeHTTP,
			UpdateOrg:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.UpdateOrg)))))))).ServeHTTP,
			DeleteOrg:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgOwnerMW(http.HandlerFunc(h.DeleteOrg)))))))).ServeHTTP,
			ListUserOrgs:        corsMW(authMW(http.HandlerFunc(h.ListUserOrgs))).ServeHTTP,
			CountUserOrgs:       corsMW(authMW(http.HandlerFunc(h.CountUserOrgs))).ServeHTTP,
			ListOrgMembers:      corsMW(rateLimitMW(authMW(orgMemberMW(http.HandlerFunc(h.ListOrgMembers))))).ServeHTTP,
			CountOrgMembers:     corsMW(authMW(orgMemberMW(http.HandlerFunc(h.CountOrgMembers)))).ServeHTTP,
			RemoveOrgMember:     corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.RemoveMember)))))))).ServeHTTP,
			UpdateOrgMemberRole: corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.UpdateMemberRole)))))))).ServeHTTP,
			// Admin — organizations: platform-admin oversight, gated by
			// adminMW (RoleAdmin), not org membership — deliberately not
			// orgMemberMW/orgAdminMW/orgOwnerMW, since the whole point is to
			// act on an org the caller isn't necessarily a member of.
			AdminListOrgs:            corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListOrgs))))).ServeHTTP,
			AdminGetOrg:              corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminGetOrg))))).ServeHTTP,
			AdminListOrgMembers:      corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListOrgMembers))))).ServeHTTP,
			AdminAddOrgMember:        corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminAddOrgMember))))))).ServeHTTP,
			AdminDeleteOrg:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminDeleteOrg))))))).ServeHTTP,
			AdminRemoveOrgMember:     corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminRemoveOrgMember))))))).ServeHTTP,
			AdminUpdateOrgMemberRole: corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminUpdateOrgMemberRole))))))).ServeHTTP,
			AdminListUserOrgs:        corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListUserOrgs))))).ServeHTTP,
			LeaveOrg:                 corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(http.HandlerFunc(h.LeaveOrg))))))).ServeHTTP,
			SetActiveOrg:             corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.SetActiveOrg)))))).ServeHTTP,
			ClearActiveOrg:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ClearActiveOrg)))))).ServeHTTP,
			CreateOrgInvite:          corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.CreateOrgInvite)))))))).ServeHTTP,
			AcceptOrgInvite:          corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.AcceptOrgInvite)))))).ServeHTTP,
			ListOrgInvites:           corsMW(rateLimitMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.ListOrgInvites)))))).ServeHTTP,
			CountOrgInvites:          corsMW(rateLimitMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.CountOrgInvites)))))).ServeHTTP,
			ResendOrgInvite:          corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.ResendOrgInvite)))))))).ServeHTTP,
			DeleteOrgInvite:          corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.DeleteOrgInvite)))))))).ServeHTTP,
		},
	}, nil
}

// AuditDeliveryStats returns the current durable-delivery observability
// surface: pending backlog, oldest undelivered age, and the cumulative
// delivery counters (record_lost, dead_lettered, delivery_dropped, …). Nil
// when audit logging is disabled.
func (a *Auth) AuditDeliveryStats(ctx context.Context) *audit.DeliveryStats {
	if a.auditService == nil {
		return nil
	}
	stats := a.auditService.DeliveryStats(ctx)
	return &stats
}

func (a *Auth) Close() {
	if a.maintenance != nil {
		a.maintenance.stop()
	}
	// Stop audit service first — workers may need DB to flush remaining events.
	if a.auditService != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.auditService.Stop(ctx)
	}
	// Only close a rate-limit Store this library constructed itself (the
	// default path, never touched by WithRateLimitStore/WithRateLimit) — a
	// consumer-supplied Store is a live object the consumer owns.
	if !a.cfg.set.rateLimitStore && a.cfg.rateLimit != nil {
		if closer, ok := a.cfg.rateLimit.Store.(ratelimit.StoreCloser); ok {
			closer.Close()
		}
	}
	// The 2FA notify store has no such caveat — New always builds it.
	if closer, ok := a.twoFactorStore.(ratelimit.StoreCloser); ok {
		closer.Close()
	}
	if a.cfg.app.Database.opened && a.db != nil {
		a.db.Close()
	}
}
