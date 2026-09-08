package goauth

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/emailtemplate"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/internal/crypto"
	"github.com/nazimdjebloun/go-auth/internal/handler"
	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/nazimdjebloun/go-auth/service"
	"github.com/nazimdjebloun/go-auth/token"
)

type Auth struct {
	cfg      config
	pool     *pgxpool.Pool
	db       *sqlstore.DB
	Services Services
	Handlers HandlerGroup

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
}

type Services struct {
	Auth      *service.AuthService
	Password  *service.PasswordService
	Session   *service.SessionService
	Verify    *service.VerificationService
	Invite    *service.InviteService
	Admin     *service.AdminService
	OAuth     *service.OAuthService
	Org       *service.OrgService
	OrgInvite *service.OrgInviteService
	TwoFactor *service.TwoFactorService
	AuditLog  port.AuditLogRepository
}

type HandlerGroup struct {
	Register                 http.HandlerFunc
	Login                    http.HandlerFunc
	AdminLogin               http.HandlerFunc
	Logout                   http.HandlerFunc
	ForgotPassword           http.HandlerFunc
	ResetPassword            http.HandlerFunc
	ChangePassword           http.HandlerFunc
	SetPasswordRequest       http.HandlerFunc
	SetPasswordConfirm       http.HandlerFunc
	VerifyEmail              http.HandlerFunc
	ResendVerification       http.HandlerFunc
	ResendVerificationPublic http.HandlerFunc
	ListSessions             http.HandlerFunc
	GetAllSessions           http.HandlerFunc
	RevokeSession            http.HandlerFunc
	RevokeManySessions       http.HandlerFunc
	RevokeAllSessions        http.HandlerFunc
	InviteRegister           http.HandlerFunc
	VerifyTwoFactor          http.HandlerFunc
	ResendTwoFactor          http.HandlerFunc
	Enable2FA                http.HandlerFunc
	Disable2FA               http.HandlerFunc
	RefreshToken             http.HandlerFunc
	GetMe                    http.HandlerFunc
	ChangeName               http.HandlerFunc
	DeleteAccount            http.HandlerFunc
	RequestDeleteAccount     http.HandlerFunc
	ConfirmDeleteAccount     http.HandlerFunc
	ListUsers                http.HandlerFunc
	CountUsers               http.HandlerFunc
	UpdateUserRole           http.HandlerFunc
	BanUser                  http.HandlerFunc
	UnbanUser                http.HandlerFunc
	DeleteUser               http.HandlerFunc
	RevokeUserSessions       http.HandlerFunc
	AdminCreateUser          http.HandlerFunc
	AdminListUserSessions    http.HandlerFunc
	AdminRevokeUserSession   http.HandlerFunc
	GetUserDetail            http.HandlerFunc
	AdminListAuditLogs       http.HandlerFunc
	AdminListUserAuditLogs   http.HandlerFunc
	AdminStats               http.HandlerFunc
	AdminRegistrationTrend   http.HandlerFunc
	AdminLoginActivity       http.HandlerFunc
	AdminListSessions        http.HandlerFunc
	BulkBanUsers             http.HandlerFunc
	BulkUnbanUsers           http.HandlerFunc
	BulkDeleteUsers          http.HandlerFunc
	BulkRevokeUserSessions   http.HandlerFunc
	GetInviteInfo            http.HandlerFunc
	CreateInvite             http.HandlerFunc
	ListInvites              http.HandlerFunc
	RevokeInvite             http.HandlerFunc
	CountInvites             http.HandlerFunc
	ResendInvite             http.HandlerFunc
	HardDeleteInvite         http.HandlerFunc
	BulkSendInvites          http.HandlerFunc
	BulkResendInvites        http.HandlerFunc
	BulkRevokeInvites        http.HandlerFunc
	BulkDeleteInvites        http.HandlerFunc
	OAuthInitiate            http.HandlerFunc
	OAuthCallback            http.HandlerFunc
	OAuthLink                http.HandlerFunc
	OAuthUnlink              http.HandlerFunc
	OAuthProviders           http.HandlerFunc
	CSRFToken                http.HandlerFunc
	CreateOrg                http.HandlerFunc
	GetOrg                   http.HandlerFunc
	UpdateOrg                http.HandlerFunc
	DeleteOrg                http.HandlerFunc
	ListUserOrgs             http.HandlerFunc
	CountUserOrgs            http.HandlerFunc
	ListOrgMembers           http.HandlerFunc
	CountOrgMembers          http.HandlerFunc
	RemoveOrgMember          http.HandlerFunc
	UpdateOrgMemberRole      http.HandlerFunc
	AdminListOrgs            http.HandlerFunc
	AdminGetOrg              http.HandlerFunc
	AdminListOrgMembers      http.HandlerFunc
	AdminAddOrgMember        http.HandlerFunc
	AdminDeleteOrg           http.HandlerFunc
	AdminRemoveOrgMember     http.HandlerFunc
	AdminUpdateOrgMemberRole http.HandlerFunc
	AdminListUserOrgs        http.HandlerFunc
	LeaveOrg                 http.HandlerFunc
	SetActiveOrg             http.HandlerFunc
	ClearActiveOrg           http.HandlerFunc
	CreateOrgInvite          http.HandlerFunc
	AcceptOrgInvite          http.HandlerFunc
	ListOrgInvites           http.HandlerFunc
	CountOrgInvites          http.HandlerFunc
	ResendOrgInvite          http.HandlerFunc
	DeleteOrgInvite          http.HandlerFunc
}

// New builds the Auth instance from a config produced by NewConfig(opts...)
// — the only supported way to configure go-auth. NewConfig is what runs
// validate() (required fields, secret length, origin policy, rate-limit
// settings, and everything else in config.validate()); the config type
// itself is unexported, so there is no way to construct one any other way.
// The validated check below is belt-and-suspenders defense in depth against
// silently proceeding with unvalidated — and in the case of an empty
// secret, cryptographically unsafe — settings.
func New(cfg config) (*Auth, error) {
	if !cfg.validated {
		return nil, fmt.Errorf(
			"goauth: config was not built via NewConfig(opts...) — " +
				"construct it with goauth.NewConfig(goauth.WithApp(...), ...) so " +
				"required fields and security settings are validated",
		)
	}
	if cfg.environment.normalize() == EnvironmentDev && cfg.logger != nil {
		cfg.logger.Warn("goauth: running in dev environment", "cookie_secure", cfg.cookieSecure)
	}

	// Derive all cryptographic keys from the single application secret.
	keys := keyring.Derive([]byte(cfg.secret))

	// The double-submit token layer is on unless explicitly disabled. A nil
	// CSRFToken means "build one with defaults", not "off" — middleware.CSRFToken
	// treats a nil config as a pass-through, so disabling is expressed by
	// leaving csrfToken nil here.
	if cfg.disableCSRFToken {
		cfg.csrfToken = nil
		if cfg.logger != nil {
			cfg.logger.Warn("goauth: CSRF double-submit token disabled",
				"note", "origin/referer checking still applies",
				"fix", "re-enable by removing SecurityConfig.DisableCSRFToken")
		}
	} else if cfg.csrfToken == nil {
		cfg.csrfToken = &middleware.CSRFTokenConfig{
			CookieName: "_csrf",
			HeaderName: "X-CSRF-Token",
			CookiePath: "/",
		}
	}
	if cfg.csrfToken != nil {
		cfg.csrfToken.CookieSecure = cfg.cookieSecure
		cfg.csrfToken.Secret = keys.CSRF
		cfg.csrfToken.Logger = cfg.logger
		// Default the token cookie's scope to the session cookie's. A
		// deployment that widened the session cookie to ".example.com" so a
		// sibling subdomain could hold a session almost certainly needs the
		// CSRF token readable there too — and a session that works while
		// every mutation 403s is the worst of the two failure modes, because
		// it looks like a permissions bug rather than a cookie-scope one.
		// An explicit CookieDomain still wins.
		if cfg.csrfToken.CookieDomain == "" {
			cfg.csrfToken.CookieDomain = cfg.cookie.Domain
		}

		// SameSite=None and ExposeCSRFTokenInBody are the same decision seen from
		// two sides: one lets the cookie be *sent* cross-site, the other lets
		// the frontend *read* the token it has to echo back. A browser
		// frontend needs both or neither, and setting one alone produces a
		// deployment that half-works in a way that reads as a bug in this
		// library rather than a config mismatch — reads fine, every write
		// 403s, or nothing authenticates at all.
		//
		// A warning, not a rejection: a native or mobile client keeps its own
		// cookie jar and is not subject to SameSite, so either setting on its
		// own is legitimate there.
		if cfg.logger != nil {
			crossSiteCookie := cfg.cookie.SameSite == http.SameSiteNoneMode
			switch {
			case crossSiteCookie && !cfg.csrfToken.ExposeCSRFTokenInBody:
				cfg.logger.Warn("goauth: cookie SameSite=None without CSRFTokenConfig.ExposeCSRFTokenInBody — a cross-site browser frontend receives the session cookie but cannot read the CSRF token, so every state-changing request will 403")
			case !crossSiteCookie && cfg.csrfToken.ExposeCSRFTokenInBody:
				cfg.logger.Warn("goauth: CSRFTokenConfig.ExposeCSRFTokenInBody without cookie SameSite=None — a cross-site browser frontend can read the CSRF token but is never sent the session cookie, so every request arrives unauthenticated",
					"same_site", cfg.cookie.SameSite)
			}
		}
	}

	var pool *pgxpool.Pool
	var sqlDB *sqlstore.DB
	var sessRepo *sqlstore.SessionRepository

	if cfg.database.Driver == "" {
		cfg.database.Driver = DriverPostgres
	}
	switch cfg.database.Driver {
	case DriverPostgres:
		// supported natively
	case DriverSQLite:
		if !isDriverRegistered("sqlite") && !isDriverRegistered("sqlite3") {
			return nil, fmt.Errorf(
				"goauth: sqlite driver not registered — add the following import to your main package:\n\n\t_ \"modernc.org/sqlite\"",
			)
		}
	case DriverMySQL:
		if !isDriverRegistered("mysql") {
			return nil, fmt.Errorf(
				"goauth: mysql driver not registered — add the following import to your main package:\n\n\t_ \"github.com/go-sql-driver/mysql\"",
			)
		}
		// Only checkable when go-auth opens the connection itself — a
		// consumer-provided *sql.DB is already open and its DSN is unknown.
		if cfg.database.URL != "" {
			if err := validateMySQLDSN(cfg.database.URL); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("goauth: unsupported driver %q", cfg.database.Driver)
	}

	switch {
	case cfg.database.Pool != nil:
		pool = cfg.database.Pool
		rawDB := stdlib.OpenDBFromPool(pool)
		sqlDB = sqlstore.NewDB(rawDB, string(DriverPostgres))
		sessRepo = sqlstore.NewSessionRepository(sqlDB)
	case cfg.database.DB != nil:
		sqlDB = sqlstore.NewDB(cfg.database.DB, string(cfg.database.Driver))
		sessRepo = sqlstore.NewSessionRepository(sqlDB)
	case cfg.database.URL != "":
		driverName := sqlDriverName(cfg.database.Driver)
		if cfg.database.Driver == DriverSQLite {
			// sqlDriverName assumes modernc.org/sqlite ("sqlite"), but the
			// registration check above also accepts mattn/go-sqlite3
			// ("sqlite3") — use whichever is actually registered so sql.Open
			// doesn't fail with "unknown driver" after registration passed.
			driverName = resolveSQLiteDriverName()
		}
		db, err := sql.Open(driverName, cfg.database.URL)
		if err != nil {
			return nil, fmt.Errorf("goauth: open database: %w", err)
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, fmt.Errorf("goauth: ping database: %w", err)
		}
		cfg.database.opened = true
		sqlDB = sqlstore.NewDB(db, string(cfg.database.Driver))
		sessRepo = sqlstore.NewSessionRepository(sqlDB)
		if cfg.database.Driver == DriverPostgres {
			pool, err = pgxpool.New(context.Background(), cfg.database.URL)
			if err != nil {
				db.Close()
				return nil, fmt.Errorf("goauth: create connection pool: %w", err)
			}
			cfg.database.poolOpened = true
		}
	default:
		return nil, fmt.Errorf("goauth: no database pool or DSN provided")
	}

	userRepo := sqlstore.NewUserRepository(sqlDB)
	sessionRepoSQL := sqlstore.NewSessionRepository(sqlDB)
	tokenRepo := sqlstore.NewTokenRepository(sqlDB)
	inviteRepo := sqlstore.NewInviteRepository(sqlDB)
	providerAccountRepo := sqlstore.NewProviderAccountRepository(sqlDB)
	if keys.OAuthEnc != nil {
		enc, _ := crypto.NewEncryptor(keys.OAuthEnc)
		providerAccountRepo.WithDecryptor(enc.Decrypt)
	}
	auditLogRepo := sqlstore.NewAuditLogRepository(sqlDB)

	hasherImpl := hasher.New(bcryptCost)
	genImpl := token.New()

	var mailer port.Mailer
	if cfg.mailer != nil {
		mailer = cfg.mailer
	} else if cfg.email != nil {
		m, err := NewSMTPMailer(*cfg.email)
		if err != nil {
			return nil, err
		}
		mailer = m
	}

	var templateProvider port.TemplateProvider
	var urlValidator *port.URLValidator
	if cfg.templateProvider != nil {
		templateProvider = cfg.templateProvider
	} else {
		allowHTTP := cfg.allowHTTPURLs
		urlValidator = &port.URLValidator{AllowHTTP: allowHTTP}
		p, err := emailtemplate.New(urlValidator)
		if err != nil {
			return nil, err
		}
		templateProvider = p
	}

	// Audit service
	var auditSvc *audit.AuditService
	var auditPub service.AuditPublisher
	if cfg.audit.Enabled {
		auditCfg := audit.AuditServiceConfig{
			FailureMode:   cfg.audit.FailureMode,
			QueueSize:     cfg.audit.QueueSize,
			Workers:       cfg.audit.Workers,
			BatchSize:     cfg.audit.BatchSize,
			FlushInterval: cfg.audit.FlushInterval,
			RetentionDays: cfg.audit.RetentionDays,
		}
		auditSvc = audit.NewAuditService(auditCfg, cfg.logger)
		auditSvc.AddSink(audit.NewSQLAuditSink(sqlDB.DB, sqlDB.Driver()))
		auditSvc.AddSink(audit.NewLoggerSink(cfg.logger))
		for _, sink := range append(append([]audit.EventSink(nil), cfg.audit.Sinks...), cfg.auditSinks...) {
			auditSvc.AddSink(sink)
		}
		auditSvc.Start(context.Background())
		auditPub = auditSvc
	}

	commonCfg := service.CommonConfig{
		AppName:    cfg.appName,
		BaseURL:    cfg.baseURL,
		SessionTTL: cfg.sessionTTL,
		TokenTTL:   cfg.tokenTTL,
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
		VerificationResendInterval: cfg.verificationResendInterval,
		PasswordPolicy:             cfg.passwordPolicy,
		TemplateProvider:           templateProvider,
		URLValidator:               urlValidator,

		RequireEmail2FA:                  cfg.requireEmail2FA,
		DefaultTwoFactorEnabled:          cfg.defaultTwoFactorEnabled,
		TwoFactorCodeTTL:                 cfg.twoFactorCodeTTL,
		TwoFactorBindingKey:              keys.TwoFactor,
		DisableTwoFactorChallengeBinding: cfg.disableTwoFactorChallengeBinding,
		TwoFactorChallengeCookieName:     cfg.twoFactorChallengeCookieName,
		DisableAdminTwoFactor:            cfg.disableAdminTwoFactor,
	}

	sessionCfg := service.DefaultSessionConfig()
	sessionCfg.Duration = cfg.sessionTTL
	sessionCfg.IdleTTL = cfg.sessionIdleTTL
	sessionCfg.RefreshTTL = cfg.refreshTokenTTL
	sessionCfg.MaxLifetime = cfg.maxLifetime
	sessionCfg.GraceWindow = cfg.graceWindow
	sessionCfg.TouchDebounce = cfg.touchDebounce
	sessionCfg.CookieName = cfg.cookie.Name
	sessionCfg.RefreshCookieName = cfg.cookie.RefreshName
	sessionCfg.Domain = cfg.cookie.Domain
	sessionCfg.Path = cfg.cookie.Path
	sessionCfg.Secure = cfg.cookieSecure
	sessionCfg.SameSite = cfg.cookie.SameSite
	sessionCfg.Logger = cfg.logger
	sessionCfg.Audit = auditPub

	sessSvc := service.NewSessionService(sessRepo, genImpl, sessionCfg)

	verifySvc := service.NewVerificationService(userRepo, tokenRepo, genImpl, mailer, serviceCfg)

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
	twoFactorSvc := service.NewTwoFactorService(userRepo, sessionRepoSQL, tokenRepo, hasherImpl, mailer, twoFactorStore, serviceCfg, sessSvc)

	authSvc := service.NewAuthService(userRepo, sessionRepoSQL, tokenRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc, verifySvc, twoFactorSvc)
	passSvc := service.NewPasswordService(userRepo, tokenRepo, hasherImpl, genImpl, mailer, sessionRepoSQL, serviceCfg)
	inviteSvc := service.NewInviteService(userRepo, sessionRepoSQL, inviteRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc, twoFactorSvc)
	adminSvc := service.NewAdminService(userRepo, sessionRepoSQL, providerAccountRepo, auditLogRepo, hasherImpl, serviceCfg, sessSvc)

	// Attach logger to session repository
	if cfg.logger != nil {
		sessionRepoSQL.WithLogger(cfg.logger)
	}

	// Build OAuth providers from registered WithProvider calls
	oauthProviders := make(map[string]port.OAuthProvider)
	for _, p := range cfg.providers {
		if p == nil {
			return nil, fmt.Errorf("goauth: nil provider registered via WithProvider")
		}
		name := p.Name()
		if name == "" {
			return nil, fmt.Errorf("goauth: provider with empty name registered via WithProvider")
		}
		if _, exists := oauthProviders[name]; exists {
			return nil, fmt.Errorf("goauth: duplicate provider %q", name)
		}
		oauthProviders[name] = p
	}

	var oauthSvc *service.OAuthService
	if len(oauthProviders) > 0 {
		var encryptor *crypto.Encryptor
		if keys.OAuthEnc != nil {
			encryptor, _ = crypto.NewEncryptor(keys.OAuthEnc)
		}
		oauthCfg := service.OAuthServiceConfig{
			CommonConfig:             commonCfg,
			RequireEmailVerification: cfg.registration.RequireEmailVerification,
			EnableOAuth:              cfg.registration.EnableOAuth,
			InviteOnly:               !cfg.registration.AllowPublic,
			Encryptor:                encryptor,
		}
		oauthSvc = service.NewOAuthService(oauthProviders, providerAccountRepo, userRepo, tokenRepo, hasherImpl, genImpl, sessSvc, verifySvc, oauthCfg)
	}

	var orgSvc *service.OrgService
	var orgInviteSvc *service.OrgInviteService
	var orgRepo port.OrgRepository
	if cfg.organizations.Enable {
		orgRepo = sqlstore.NewOrgRepository(sqlDB)
		orgInviteRepo := sqlstore.NewOrgInviteRepository(sqlDB)
		orgSvc = service.NewOrgService(orgRepo, userRepo, sessRepo, sqlDB, service.OrgServiceConfig{
			MaxOrgsPerUser: cfg.organizations.MaxOrgsPerUser,
			Logger:         cfg.logger,
			Audit:          auditPub,
		})
		orgInviteSvc = service.NewOrgInviteService(orgInviteRepo, orgRepo, userRepo, sqlDB, genImpl, mailer, service.OrgInviteServiceConfig{
			MaxOrgsPerUser:   cfg.organizations.MaxOrgsPerUser,
			InviteTTL:        cfg.organizations.InviteTTL,
			BaseURL:          cfg.baseURL,
			AppName:          cfg.appName,
			TemplateProvider: templateProvider,
			URLValidator:     urlValidator,
			Logger:           cfg.logger,
			Audit:            auditPub,
		})
	}

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

	h := handler.NewWithLogger(handler.Services{
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
	}, cfg.logger, cfg.csrfToken, clientIPCfg)

	// OAuth handlers (separate because they need baseURL and session service for cookies)
	oauthHandlers := handler.NewOAuthHandlers(oauthSvc, sessSvc, cfg.baseURL, cfg.csrfToken, clientIPCfg)

	authMW := middleware.AuthMiddleware(sessSvc, userRepo, cfg.logger)
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
	csrfMW := middleware.OriginCheck(cfg.allowedOrigins, cfg.allowMissingCSRFHeaders, trustedIPs, cfg.logger)
	csrfTokenMW := middleware.CSRFToken(cfg.csrfToken)
	corsMW := middleware.CORS(cfg.allowedOrigins)

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

	return &Auth{
		cfg:              cfg,
		pool:             pool,
		db:               sqlDB,
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
			ChangePassword:           corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ChangePassword))))).ServeHTTP,
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
			DeleteAccount:        corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.DeleteAccount))))).ServeHTTP,
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
			// levels documented in ORGS.md §6. CreateOrg/ListUserOrgs/
			// AcceptOrgInvite/SetActiveOrg/ClearActiveOrg have no {orgID}
			// path segment (self-service or org resolved from a code/body),
			// so they stay authMW-only; SetActiveOrg/AcceptInvite already
			// check membership inside the service layer.
			CreateOrg:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.CreateOrg)))))).ServeHTTP,
			GetOrg:              corsMW(authMW(orgMemberMW(http.HandlerFunc(h.GetOrg)))).ServeHTTP,
			UpdateOrg:           corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.UpdateOrg))))))).ServeHTTP,
			DeleteOrg:           corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgOwnerMW(http.HandlerFunc(h.DeleteOrg))))))).ServeHTTP,
			ListUserOrgs:        corsMW(authMW(http.HandlerFunc(h.ListUserOrgs))).ServeHTTP,
			CountUserOrgs:       corsMW(authMW(http.HandlerFunc(h.CountUserOrgs))).ServeHTTP,
			ListOrgMembers:      corsMW(authMW(orgMemberMW(http.HandlerFunc(h.ListOrgMembers)))).ServeHTTP,
			CountOrgMembers:     corsMW(authMW(orgMemberMW(http.HandlerFunc(h.CountOrgMembers)))).ServeHTTP,
			RemoveOrgMember:     corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.RemoveMember))))))).ServeHTTP,
			UpdateOrgMemberRole: corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.UpdateMemberRole))))))).ServeHTTP,
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
			LeaveOrg:                 corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(http.HandlerFunc(h.LeaveOrg)))))).ServeHTTP,
			SetActiveOrg:             corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.SetActiveOrg))))).ServeHTTP,
			ClearActiveOrg:           corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ClearActiveOrg))))).ServeHTTP,
			CreateOrgInvite:          corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.CreateOrgInvite)))))))).ServeHTTP,
			AcceptOrgInvite:          corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.AcceptOrgInvite))))).ServeHTTP,
			ListOrgInvites:           corsMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.ListOrgInvites))))).ServeHTTP,
			CountOrgInvites:          corsMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.CountOrgInvites))))).ServeHTTP,
			ResendOrgInvite:          corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.ResendOrgInvite))))))).ServeHTTP,
			DeleteOrgInvite:          corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.DeleteOrgInvite))))))).ServeHTTP,
		},
	}, nil
}

func (a *Auth) Close() {
	// Stop audit service first — workers may need DB to flush remaining events.
	if a.auditService != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.auditService.Stop(ctx)
	}
	// Only close a rate-limit Store this library constructed itself (the
	// default path, never touched by WithRateLimitStore/WithRateLimit) — a
	// consumer-supplied Store is a live object the consumer owns.
	if !a.cfg.rateLimitStoreExplicit && a.cfg.rateLimit != nil {
		if closer, ok := a.cfg.rateLimit.Store.(ratelimit.StoreCloser); ok {
			closer.Close()
		}
	}
	// The 2FA notify store has no such caveat — New always builds it.
	if closer, ok := a.twoFactorStore.(ratelimit.StoreCloser); ok {
		closer.Close()
	}
	if a.cfg.database.poolOpened && a.pool != nil {
		a.pool.Close()
	}
	if a.cfg.database.opened && a.db != nil {
		a.db.Close()
	}
}
