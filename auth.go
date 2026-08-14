package goauth

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/emailtemplate"
	"github.com/nazimdjebloun/go-auth/internal/handler"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/internal/crypto"
	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/internal/routes"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/nazimdjebloun/go-auth/service"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
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
	CheckSession             http.HandlerFunc
	RefreshToken             http.HandlerFunc
	GetMe                    http.HandlerFunc
	ChangeName               http.HandlerFunc
	DeleteAccount            http.HandlerFunc
	RequestDeleteAccount     http.HandlerFunc
	ConfirmDeleteAccount     http.HandlerFunc
	ListUsers                http.HandlerFunc
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
	GetInviteInfo            http.HandlerFunc
	CreateInvite             http.HandlerFunc
	ListInvites              http.HandlerFunc
	RevokeInvite             http.HandlerFunc
	ResendInvite             http.HandlerFunc
	HardDeleteInvite         http.HandlerFunc
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
	ListOrgMembers           http.HandlerFunc
	RemoveOrgMember          http.HandlerFunc
	UpdateOrgMemberRole      http.HandlerFunc
	LeaveOrg                 http.HandlerFunc
	SetActiveOrg             http.HandlerFunc
	ClearActiveOrg           http.HandlerFunc
	CreateOrgInvite          http.HandlerFunc
	AcceptOrgInvite          http.HandlerFunc
	ListOrgInvites           http.HandlerFunc
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
func New(config config) (*Auth, error) {
	if !config.validated {
		return nil, fmt.Errorf(
			"goauth: config was not built via NewConfig(opts...) — " +
				"construct it with goauth.NewConfig(goauth.WithApp(...), ...) so " +
				"required fields and security settings are validated",
		)
	}
	if config.environment.normalize() == EnvironmentDev && config.logger != nil {
		config.logger.Warn("goauth: running in dev environment", "cookie_secure", config.cookieSecure)
	}

	// Derive all cryptographic keys from the single application secret.
	keys := keyring.Derive([]byte(config.secret))

	// The double-submit token layer is on unless explicitly disabled. A nil
	// CSRFToken means "build one with defaults", not "off" — middleware.CSRFToken
	// treats a nil config as a pass-through, so disabling is expressed by
	// leaving csrfToken nil here.
	if config.disableCSRFToken {
		config.csrfToken = nil
		if config.logger != nil {
			config.logger.Warn("goauth: CSRF double-submit token disabled",
				"note", "origin/referer checking still applies",
				"fix", "re-enable by removing SecurityConfig.DisableCSRFToken")
		}
	} else if config.csrfToken == nil {
		config.csrfToken = &middleware.CSRFTokenConfig{
			CookieName: "_csrf",
			HeaderName: "X-CSRF-Token",
			CookiePath: "/",
		}
	}
	if config.csrfToken != nil {
		config.csrfToken.CookieSecure = config.cookieSecure
		config.csrfToken.Secret = keys.CSRF
		config.csrfToken.Logger = config.logger
	}

	var pool *pgxpool.Pool
	var sqlDB *sqlstore.DB
	var sessRepo *sqlstore.SessionRepository

	if config.database.Driver == "" {
		config.database.Driver = DriverPostgres
	}
	switch config.database.Driver {
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
		if config.database.URL != "" {
			if err := validateMySQLDSN(config.database.URL); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("goauth: unsupported driver %q", config.database.Driver)
	}

	switch {
	case config.database.Pool != nil:
		pool = config.database.Pool
		rawDB := stdlib.OpenDBFromPool(pool)
		sqlDB = sqlstore.NewDB(rawDB, string(DriverPostgres))
		sessRepo = sqlstore.NewSessionRepository(sqlDB)
	case config.database.DB != nil:
		sqlDB = sqlstore.NewDB(config.database.DB, string(config.database.Driver))
		sessRepo = sqlstore.NewSessionRepository(sqlDB)
	case config.database.URL != "":
		driverName := sqlDriverName(config.database.Driver)
		if config.database.Driver == DriverSQLite {
			// sqlDriverName assumes modernc.org/sqlite ("sqlite"), but the
			// registration check above also accepts mattn/go-sqlite3
			// ("sqlite3") — use whichever is actually registered so sql.Open
			// doesn't fail with "unknown driver" after registration passed.
			driverName = resolveSQLiteDriverName()
		}
		db, err := sql.Open(driverName, config.database.URL)
		if err != nil {
			return nil, fmt.Errorf("goauth: open database: %w", err)
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, fmt.Errorf("goauth: ping database: %w", err)
		}
		config.database.opened = true
		sqlDB = sqlstore.NewDB(db, string(config.database.Driver))
		sessRepo = sqlstore.NewSessionRepository(sqlDB)
		if config.database.Driver == DriverPostgres {
			pool, err = pgxpool.New(context.Background(), config.database.URL)
			if err != nil {
				db.Close()
				return nil, fmt.Errorf("goauth: create connection pool: %w", err)
			}
			config.database.poolOpened = true
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
	if config.mailer != nil {
		mailer = config.mailer
	} else if config.email != nil {
		m, err := NewSMTPMailer(*config.email)
		if err != nil {
			return nil, err
		}
		mailer = m
	}

	var templateProvider port.TemplateProvider
	var urlValidator *port.URLValidator
	if config.templateProvider != nil {
		templateProvider = config.templateProvider
	} else {
		allowHTTP := config.allowHTTPURLs
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
	if config.audit.Enabled {
		auditCfg := audit.AuditServiceConfig{
			FailureMode:   config.audit.FailureMode,
			QueueSize:     config.audit.QueueSize,
			Workers:       config.audit.Workers,
			BatchSize:     config.audit.BatchSize,
			FlushInterval: config.audit.FlushInterval,
			RetentionDays: config.audit.RetentionDays,
		}
		auditSvc = audit.NewAuditService(auditCfg, config.logger)
		auditSvc.AddSink(audit.NewSQLAuditSink(sqlDB.DB, sqlDB.Driver()))
		auditSvc.AddSink(audit.NewLoggerSink(config.logger))
		for _, sink := range append(append([]audit.EventSink(nil), config.audit.Sinks...), config.auditSinks...) {
			auditSvc.AddSink(sink)
		}
		auditSvc.Start(context.Background())
		auditPub = auditSvc
	}

	commonCfg := service.CommonConfig{
		AppName:    config.appName,
		BaseURL:    config.baseURL,
		SessionTTL: config.sessionTTL,
		TokenTTL:   config.tokenTTL,
		Logger:     config.logger,
		Audit:      auditPub,
	}

	serviceCfg := service.Config{
		CommonConfig:               commonCfg,
		InviteOnly:                 !config.registration.AllowPublic,
		EnableEmailPassword:        config.registration.EnableEmailPassword,
		EnableOAuth:                config.registration.EnableOAuth,
		EnableInvite:               config.registration.EnableInvite,
		RequireEmailVerification:   config.registration.RequireEmailVerification,
		InviteTTL:                  config.registration.InviteTTL,
		VerificationCodeTTL:        config.registration.VerificationCodeTTL,
		VerificationResendInterval: config.verificationResendInterval,
		PasswordPolicy:             config.passwordPolicy,
		TemplateProvider:           templateProvider,
		URLValidator:               urlValidator,

		RequireEmail2FA:                  config.requireEmail2FA,
		DefaultTwoFactorEnabled:          config.defaultTwoFactorEnabled,
		TwoFactorCodeTTL:                 config.twoFactorCodeTTL,
		TwoFactorBindingKey:              keys.TwoFactor,
		DisableTwoFactorChallengeBinding: config.disableTwoFactorChallengeBinding,
		TwoFactorChallengeCookieName:     config.twoFactorChallengeCookieName,
		DisableAdminTwoFactor:            config.disableAdminTwoFactor,
	}

	sessionCfg := service.DefaultSessionConfig()
	sessionCfg.Duration = config.sessionTTL
	sessionCfg.IdleTTL = config.sessionIdleTTL
	sessionCfg.RefreshTTL = config.refreshTokenTTL
	sessionCfg.MaxLifetime = config.maxLifetime
	sessionCfg.GraceWindow = config.graceWindow
	sessionCfg.TouchDebounce = config.touchDebounce
	sessionCfg.CookieName = config.cookie.Name
	sessionCfg.RefreshCookieName = config.cookie.RefreshName
	sessionCfg.Domain = config.cookie.Domain
	sessionCfg.Path = config.cookie.Path
	sessionCfg.Secure = config.cookieSecure
	sessionCfg.SameSite = config.cookie.SameSite
	sessionCfg.Logger = config.logger
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
		ratelimit.WithStoreLogger(config.logger),
	)
	twoFactorSvc := service.NewTwoFactorService(userRepo, sessionRepoSQL, tokenRepo, hasherImpl, mailer, twoFactorStore, serviceCfg, sessSvc)

	authSvc := service.NewAuthService(userRepo, sessionRepoSQL, tokenRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc, verifySvc, twoFactorSvc)
	passSvc := service.NewPasswordService(userRepo, tokenRepo, hasherImpl, genImpl, mailer, sessionRepoSQL, serviceCfg)
	inviteSvc := service.NewInviteService(userRepo, sessionRepoSQL, inviteRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc, twoFactorSvc)
	adminSvc := service.NewAdminService(userRepo, sessionRepoSQL, providerAccountRepo, hasherImpl, serviceCfg, sessSvc)

	// Attach logger to session repository
	if config.logger != nil {
		sessionRepoSQL.WithLogger(config.logger)
	}

	// Build OAuth providers from registered WithProvider calls
	oauthProviders := make(map[string]port.OAuthProvider)
	for _, p := range config.providers {
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
			RequireEmailVerification: config.registration.RequireEmailVerification,
			EnableOAuth:              config.registration.EnableOAuth,
			InviteOnly:               !config.registration.AllowPublic,
			Encryptor:                encryptor,
		}
		oauthSvc = service.NewOAuthService(oauthProviders, providerAccountRepo, userRepo, tokenRepo, hasherImpl, genImpl, sessSvc, verifySvc, oauthCfg)
	}

	var orgSvc *service.OrgService
	var orgInviteSvc *service.OrgInviteService
	var orgRepo port.OrgRepository
	if config.organizations.Enable {
		orgRepo = sqlstore.NewOrgRepository(sqlDB)
		orgInviteRepo := sqlstore.NewOrgInviteRepository(sqlDB)
		orgSvc = service.NewOrgService(orgRepo, userRepo, sessRepo, sqlDB, service.OrgServiceConfig{
			MaxOrgsPerUser: config.organizations.MaxOrgsPerUser,
			Logger:         config.logger,
			Audit:          auditPub,
		})
		orgInviteSvc = service.NewOrgInviteService(orgInviteRepo, orgRepo, userRepo, sqlDB, genImpl, mailer, service.OrgInviteServiceConfig{
			MaxOrgsPerUser:   config.organizations.MaxOrgsPerUser,
			InviteTTL:        config.organizations.InviteTTL,
			BaseURL:          config.baseURL,
			AppName:          config.appName,
			TemplateProvider: templateProvider,
			URLValidator:     urlValidator,
			Logger:           config.logger,
			Audit:            auditPub,
		})
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
	}, config.logger, config.csrfToken)

	// OAuth handlers (separate because they need baseURL and session service for cookies)
	oauthHandlers := handler.NewOAuthHandlers(oauthSvc, sessSvc, config.baseURL, config.csrfToken)

	authMW := middleware.AuthMiddleware(sessSvc, userRepo, config.logger)
	adminMW := middleware.RequireRole(domain.RoleAdmin, config.logger)
	var trustedIPs []string
	if config.rateLimit != nil {
		config.rateLimit.Logger = config.logger
		trustedIPs = config.rateLimit.TrustedIPs
		if !config.rateLimit.Enabled && config.logger != nil {
			config.logger.Warn("goauth: rate limiting is disabled — this is insecure for production",
				"fix", "re-enable with WithRateLimitEnabled(true) or use a trusted edge rate limiter")
		}
		if config.rateLimit.Enabled && config.logger != nil && ratelimit.IsDefaultStore(config.rateLimit.Store) {
			// Heuristic reminder, not a diagnosis — the library has no way to
			// detect "multiple instances" directly, so this fires on every
			// process using the default store, dev included.
			config.logger.Warn("goauth: rate limiting is using the default in-memory store, which does not share state across instances",
				"fix", "if you run more than one instance behind a load balancer, use WithRateLimitStore with a shared store (e.g. Redis) or limits apply per-instance rather than globally")
		}
	}
	rateLimitMW := middleware.RateLimit(config.rateLimit)
	csrfMW := middleware.OriginCheck(config.allowedOrigins, config.allowMissingCSRFHeaders, trustedIPs, config.logger)
	csrfTokenMW := middleware.CSRFToken(config.csrfToken)
	corsMW := middleware.CORS(config.allowedOrigins)

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
		cfg:              config,
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
			VerifyTwoFactor:      corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.VerifyTwoFactor))))).ServeHTTP,
			ResendTwoFactor:      corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.ResendTwoFactor))))).ServeHTTP,
			Enable2FA:            corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.Enable2FA)))))).ServeHTTP,
			Disable2FA:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.Disable2FA)))))).ServeHTTP,
			GetInviteInfo:        corsMW(rateLimitMW(http.HandlerFunc(h.GetInviteInfo))).ServeHTTP,
			GetMe:                corsMW(authMW(http.HandlerFunc(h.GetMe))).ServeHTTP,
			CheckSession:         corsMW(http.HandlerFunc(h.CheckAuth)).ServeHTTP,
			RefreshToken:         corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.RefreshToken))))).ServeHTTP,
			ChangeName:           corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ChangeName))))).ServeHTTP,
			DeleteAccount:        corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.DeleteAccount))))).ServeHTTP,
			RequestDeleteAccount: corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RequestDeleteAccount)))))).ServeHTTP,
			// Confirm delete requires an authenticated session (user ID from context only).
			ConfirmDeleteAccount: corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ConfirmDeleteAccount)))))).ServeHTTP,
			// Admin endpoints: CORS outer, then rate limit, then auth + admin role check.
			ListUsers:              corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.ListUsers))))).ServeHTTP,
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
			CreateInvite:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.CreateInvite))))))).ServeHTTP,
			ListInvites:            corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.ListInvites))))).ServeHTTP,
			RevokeInvite:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.RevokeInvite))))))).ServeHTTP,
			ResendInvite:           corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.ResendInvite))))))).ServeHTTP,
			HardDeleteInvite:       corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.HardDeleteInvite))))))).ServeHTTP,
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
			ListOrgMembers:      corsMW(authMW(orgMemberMW(http.HandlerFunc(h.ListOrgMembers)))).ServeHTTP,
			RemoveOrgMember:     corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.RemoveMember))))))).ServeHTTP,
			UpdateOrgMemberRole: corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.UpdateMemberRole))))))).ServeHTTP,
			LeaveOrg:            corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(http.HandlerFunc(h.LeaveOrg)))))).ServeHTTP,
			SetActiveOrg:        corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.SetActiveOrg))))).ServeHTTP,
			ClearActiveOrg:      corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ClearActiveOrg))))).ServeHTTP,
			CreateOrgInvite:     corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.CreateOrgInvite)))))))).ServeHTTP,
			AcceptOrgInvite:     corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.AcceptOrgInvite))))).ServeHTTP,
			ListOrgInvites:      corsMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.ListOrgInvites))))).ServeHTTP,
			ResendOrgInvite:     corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.ResendOrgInvite))))))).ServeHTTP,
			DeleteOrgInvite:     corsMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.DeleteOrgInvite))))))).ServeHTTP,
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

// routeEntry pairs a canonical route pattern (from internal/routes) with
// the already-middleware-wrapped handler that serves it.
type routeEntry struct {
	pattern string
	handler http.Handler
}

// Mount registers every enabled route onto mux. It requires a real
// *http.ServeMux (Go 1.22+'s pattern syntax, e.g. "GET /admin/users/{id}")
// because route handlers read path parameters with r.PathValue, which only
// ServeMux populates — mounting the same handlers on chi, gin, echo, or any
// router that doesn't call r.SetPathValue itself will 404 or read an empty
// ID on every parameterized route, with no error at mount time. Bridge to
// another router by having it populate PathValue before calling into these
// handlers, or use Auth.RequireAuth/RequireAdmin/RequireOrg plus
// auth.Services.* directly and write your own routing layer.
func (a *Auth) Mount(mux *http.ServeMux) {
	// All middleware (CORS, rate limit, csrf token, origin check, auth, admin)
	// is already baked into a.Handlers — CORS outermost so preflight OPTIONS
	// short-circuits before rate limiting. Mount only registers routes; do NOT
	// wrap the mux again with a.CORS or any other middleware.
	//
	// handle registers a route and, when CORS origins are configured, also the
	// exact OPTIONS twin for the same path. OPTIONS is registered 1:1 with each
	// route go-auth owns — never a catch-all — so preflight requests for paths
	// go-auth does not own (including a consumer's own routes on a shared mux)
	// still get a normal 404/405 and never reach the CORS layer.
	preflight := len(a.cfg.allowedOrigins) > 0
	preflightPaths := make(map[string]bool)
	handle := func(pattern string, h http.Handler) {
		mux.Handle(pattern, h)
		if preflight {
			// OPTIONS is registered once per path. Multiple methods may share a
			// path (GET /auth/sessions, DELETE /auth/sessions), but preflight is
			// method-agnostic, so a duplicate registration would panic. CORS
			// short-circuits OPTIONS with 204 before the handler runs, so any
			// of the shared handlers answers it correctly.
			if i := strings.IndexByte(pattern, ' '); i > 0 {
				p := pattern[i+1:]
				if !preflightPaths[p] {
					preflightPaths[p] = true
					mux.Handle("OPTIONS "+p, h)
				}
			}
		}
	}

	entries := []routeEntry{
		{routes.Login, a.Handlers.Login},
		{routes.AdminLogin, a.Handlers.AdminLogin},
		{routes.ForgotPassword, a.Handlers.ForgotPassword},
		{routes.ResetPassword, a.Handlers.ResetPassword},
		{routes.VerifyEmail, a.Handlers.VerifyEmail},
		{routes.TwoFactorVerify, a.Handlers.VerifyTwoFactor},
		{routes.TwoFactorResend, a.Handlers.ResendTwoFactor},
		{routes.TwoFactorEnable, a.Handlers.Enable2FA},
		{routes.TwoFactorDisable, a.Handlers.Disable2FA},
		{routes.Logout, a.Handlers.Logout},
		{routes.Me, a.Handlers.GetMe},
		{routes.CheckSession, a.Handlers.CheckSession},
		{routes.CSRFToken, a.Handlers.CSRFToken},
		{routes.ChangeName, a.Handlers.ChangeName},
		{routes.ListSessions, a.Handlers.ListSessions},
		{routes.AllSessions, a.Handlers.GetAllSessions},
		{routes.RevokeSession, a.Handlers.RevokeSession},
		{routes.RevokeManySessions, a.Handlers.RevokeManySessions},
		{routes.RevokeAllSessions, a.Handlers.RevokeAllSessions},
		{routes.ChangePassword, a.Handlers.ChangePassword},
		{routes.SetPasswordRequest, a.Handlers.SetPasswordRequest},
		{routes.SetPasswordConfirm, a.Handlers.SetPasswordConfirm},
		{routes.DeleteAccount, a.Handlers.DeleteAccount},
		{routes.RequestDeleteAccount, a.Handlers.RequestDeleteAccount},
		{routes.ConfirmDeleteAccount, a.Handlers.ConfirmDeleteAccount},
		{routes.ResendVerification, a.Handlers.ResendVerification},
		{routes.ResendVerificationPublic, a.Handlers.ResendVerificationPublic},
		{routes.RefreshToken, a.Handlers.RefreshToken},
		{routes.ListUsers, a.Handlers.ListUsers},
		{routes.GetUserDetail, a.Handlers.GetUserDetail},
		{routes.UpdateUserRole, a.Handlers.UpdateUserRole},
		{routes.BanUser, a.Handlers.BanUser},
		{routes.UnbanUser, a.Handlers.UnbanUser},
		{routes.DeleteUser, a.Handlers.DeleteUser},
		{routes.AdminCreateUser, a.Handlers.AdminCreateUser},
		{routes.AdminListUserSessions, a.Handlers.AdminListUserSessions},
		{routes.AdminRevokeUserSession, a.Handlers.AdminRevokeUserSession},
		{routes.RevokeUserSessions, a.Handlers.RevokeUserSessions},
		{routes.AdminListAuditLogs, a.Handlers.AdminListAuditLogs},
		{routes.AdminListUserAuditLogs, a.Handlers.AdminListUserAuditLogs},
	}

	if a.cfg.registration.EnableEmailPassword {
		entries = append(entries, routeEntry{routes.Register, a.Handlers.Register})
	}
	if a.cfg.registration.EnableInvite {
		entries = append(entries,
			routeEntry{routes.InviteInfo, a.Handlers.GetInviteInfo},
			routeEntry{routes.InviteRegister, a.Handlers.InviteRegister},
			routeEntry{routes.CreateInvite, a.Handlers.CreateInvite},
			routeEntry{routes.ListInvites, a.Handlers.ListInvites},
			routeEntry{routes.RevokeInvite, a.Handlers.RevokeInvite},
			routeEntry{routes.ResendInvite, a.Handlers.ResendInvite},
			routeEntry{routes.HardDeleteInvite, a.Handlers.HardDeleteInvite},
		)
	}
	if a.cfg.registration.EnableOAuth && a.oAuthService != nil {
		entries = append(entries,
			routeEntry{routes.OAuthInitiate, a.Handlers.OAuthInitiate},
			routeEntry{routes.OAuthCallbackGet, a.Handlers.OAuthCallback},
			routeEntry{routes.OAuthCallbackPost, a.Handlers.OAuthCallback},
			routeEntry{routes.OAuthLink, a.Handlers.OAuthLink},
			routeEntry{routes.OAuthUnlink, a.Handlers.OAuthUnlink},
			routeEntry{routes.OAuthProviders, a.Handlers.OAuthProviders},
		)
	}
	if a.orgService != nil {
		entries = append(entries,
			routeEntry{routes.CreateOrg, a.Handlers.CreateOrg},
			routeEntry{routes.ListUserOrgs, a.Handlers.ListUserOrgs},
			routeEntry{routes.GetOrg, a.Handlers.GetOrg},
			routeEntry{routes.UpdateOrg, a.Handlers.UpdateOrg},
			routeEntry{routes.DeleteOrg, a.Handlers.DeleteOrg},
			routeEntry{routes.ListOrgMembers, a.Handlers.ListOrgMembers},
			routeEntry{routes.RemoveOrgMember, a.Handlers.RemoveOrgMember},
			routeEntry{routes.UpdateOrgMemberRole, a.Handlers.UpdateOrgMemberRole},
			routeEntry{routes.LeaveOrg, a.Handlers.LeaveOrg},
			routeEntry{routes.SetActiveOrg, a.Handlers.SetActiveOrg},
			routeEntry{routes.ClearActiveOrg, a.Handlers.ClearActiveOrg},
			routeEntry{routes.CreateOrgInvite, a.Handlers.CreateOrgInvite},
			routeEntry{routes.AcceptOrgInvite, a.Handlers.AcceptOrgInvite},
			routeEntry{routes.ListOrgInvites, a.Handlers.ListOrgInvites},
			routeEntry{routes.ResendOrgInvite, a.Handlers.ResendOrgInvite},
			routeEntry{routes.DeleteOrgInvite, a.Handlers.DeleteOrgInvite},
		)
	}

	for _, e := range entries {
		handle(e.pattern, e.handler)
	}
}

// ─── Middleware accessors ───────────────────────────────────

// RequireAuth protects a consumer route with the same session validation
// (including transparent refresh) that the built-in auth routes use. On
// success the user and session are placed in the request context — read
// them with middleware.GetUserFromContext and middleware.GetSessionFromContext.
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return a.authMW(next)
}

// RequireAdmin protects a consumer route with the admin role check used by
// the built-in /admin routes. Wrap with RequireAuth first: the check reads
// the user from the context RequireAuth populates.
func (a *Auth) RequireAdmin(next http.Handler) http.Handler {
	return a.adminMW(next)
}

// RateLimit applies the configured rate limiter to a consumer route. The
// routes mounted by Mount already have rate limiting baked in — this is for
// your own routes only.
func (a *Auth) RateLimit(next http.Handler) http.Handler {
	return a.rateLimitMW(next)
}

// RateLimitWithPattern is RateLimit for a consumer route mounted on a router
// that doesn't populate http.Request.Pattern — chi, gorilla/mux, echo, and
// anything that isn't net/http's ServeMux.
//
// Counters are keyed on the route pattern, not the request path, so a route
// with a path parameter can't be turned into an unlimited supply of fresh
// counters. Where the pattern isn't discoverable, every such route shares one
// fallback counter per client; naming it here gives the route its own:
//
//	r.Post("/widgets/{id}/publish",
//	    auth.RateLimitWithPattern("POST /widgets/{id}/publish")(publish).ServeHTTP)
//
// The string only has to be stable and one-per-route — it isn't parsed. To
// give the route its own limit as well as its own counter, add the same
// string to the rate table with WithRateLimitRoute.
//
// Don't reuse a pattern that already names one of the mounted routes: the
// pattern picks the counter, but the rate still comes from matching this
// request's own method and path, so the route would share the other route's
// counter while being charged the default rate.
func (a *Auth) RateLimitWithPattern(pattern string) func(http.Handler) http.Handler {
	return middleware.RateLimitWithPattern(a.cfg.rateLimit, pattern)
}

// CORS applies the configured CORS middleware to a consumer route. The
// routes mounted by Mount already have CORS baked in — this is for your own
// routes only.
func (a *Auth) CORS(next http.Handler) http.Handler {
	return a.corsMW(next)
}

// RequireOrg protects a consumer route with an org membership check plus a
// minimum role, using the same org repository and auth context as the built-in
// org routes. It resolves the org from the {orgID} path segment, falling back
// to the org_id query parameter, and must run after RequireAuth.
//
// When organizations are disabled the returned middleware rejects every
// request with 503 — add goauth.WithOrganizations(goauth.OrganizationConfig{
// Enable: true}) to enable them.
func (a *Auth) RequireOrg(role domain.OrgRole) func(http.Handler) http.Handler {
	if !role.IsValid() {
		panic(fmt.Sprintf(
			"goauth: invalid org role %q — use domain.OrgRoleMember, domain.OrgRoleAdmin, or domain.OrgRoleOwner",
			role,
		))
	}
	if a.orgService == nil {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error":"organizations_disabled","message":"Organizations are not enabled — add goauth.WithOrganizations(goauth.OrganizationConfig{Enable: true})"}`, http.StatusServiceUnavailable)
			})
		}
	}
	roleMW := middleware.RequireOrgRole(role)
	return func(next http.Handler) http.Handler {
		return a.orgMemberMW(roleMW(next))
	}
}

// ─── Session cookie accessors ───────────────────────────────

// SetSessionCookies writes the session and refresh cookies for a newly
// issued token pair, using the configured cookie settings. Pair it with a
// custom handler that calls a.Services.Auth.Login (or Register) directly —
// that call returns raw tokens with no cookies set; this is how you turn
// them into the same cookies the built-in handlers issue. A non-empty
// refreshToken is required to also write the refresh cookie; pass "" to
// skip it (mirrors the built-in handlers' behavior when no refresh token
// was issued).
//
// This does not rotate the CSRF token — call RotateCSRFToken separately if
// your handler needs the same "session issued" ceremony the built-in login
// handlers perform.
func (a *Auth) SetSessionCookies(w http.ResponseWriter, sessionToken, refreshToken string) {
	cfg := a.sessionService.Config()
	middleware.SetSessionCookie(w, cfg, sessionToken)
	middleware.SetRefreshCookie(w, cfg, refreshToken)
}

// ClearSessionCookies expires both the session and refresh cookies. Pair it
// with a custom handler that revokes the session itself via
// a.Services.Session.Revoke.
func (a *Auth) ClearSessionCookies(w http.ResponseWriter) {
	cfg := a.sessionService.Config()
	middleware.ClearSessionCookie(w, cfg)
	middleware.ClearRefreshCookie(w, cfg)
}

// RotateCSRFToken issues a fresh CSRF token cookie, using the configured
// CSRF settings. A no-op if the double-submit CSRF layer is disabled
// (SecurityConfig.DisableCSRFToken). Call this alongside SetSessionCookies
// in a custom login handler to match the built-in handlers, which rotate
// the CSRF token on every login/logout.
func (a *Auth) RotateCSRFToken(w http.ResponseWriter) {
	middleware.RotateCSRFToken(w, a.cfg.csrfToken)
}

// Register creates a new email/password account. input.IP and
// input.UserAgent, when set, are recorded on the resulting session and any
// audit event this produces — pass the caller's real values for a
// programmatic (non-HTTP) integration; the built-in HTTP handler already
// does this for you.
func (a *Auth) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	return a.authService.Register(ctx, input)
}

// Login authenticates an email/password account. input.IP and
// input.UserAgent, when set, are recorded on the resulting session and any
// audit event this produces.
func (a *Auth) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	return a.authService.Login(ctx, input)
}

// CompleteInviteRegistration finishes registration from an invite code.
// input.IP and input.UserAgent, when set, are recorded the same way as
// Register.
func (a *Auth) CompleteInviteRegistration(ctx context.Context, input CompleteInviteInput) (*CompleteInviteResult, error) {
	return a.inviteService.CompleteInviteRegistration(ctx, input)
}

// CheckSession validates a raw session token and returns whether it is valid.
// It checks the session exists, is not expired, and the associated user exists and is not banned.
func (a *Auth) CheckSession(ctx context.Context, tokenRaw string) bool {
	_, _, err := a.authService.ValidateSession(ctx, tokenRaw)
	return err == nil
}

// GetSession validates a raw session token and returns the associated user and session.
// Returns the user, session, and nil error on success.
// Returns nil, nil, error if the token is invalid, expired, or the user is banned.
func (a *Auth) GetSession(ctx context.Context, tokenRaw string) (*domain.User, *domain.Session, error) {
	user, session, err := a.authService.ValidateSession(ctx, tokenRaw)
	if err != nil {
		return nil, nil, err
	}
	return user, session, nil
}

func isDriverRegistered(name string) bool {
	for _, d := range sql.Drivers() {
		if d == name {
			return true
		}
	}
	return false
}

// resolveSQLiteDriverName returns whichever of "sqlite" (modernc.org/sqlite,
// the documented driver) or "sqlite3" (mattn/go-sqlite3) is actually
// registered. The registration check in New() accepts either name, so
// sql.Open must use the one that's really there instead of assuming
// "sqlite" — otherwise a consumer using mattn/go-sqlite3 passes validation
// and then fails with "unknown driver \"sqlite\"".
func resolveSQLiteDriverName() string {
	if isDriverRegistered("sqlite") {
		return "sqlite"
	}
	return "sqlite3"
}

// validateMySQLDSN rejects a MySQL DSN that's missing parseTime=true.
// go-sql-driver/mysql returns DATETIME/TIMESTAMP columns as []byte unless
// parseTime=true is set, and every sqlstore repository scans directly into
// time.Time fields — without it, the first query touching any date column
// fails with "unsupported Scan, storing driver.Value type []uint8 into type
// *time.Time". loc=UTC is recommended too: every timestamp in go-auth is
// computed via time.Now().UTC(), and without loc=UTC the driver parses
// returned times in the local server timezone, skewing expiry/TTL checks.
func validateMySQLDSN(dsn string) error {
	_, params, _ := strings.Cut(dsn, "?")
	values, err := url.ParseQuery(params)
	if err != nil || !mysqlBoolParam(values.Get("parseTime")) {
		return fmt.Errorf(
			"goauth: mysql DSN is missing \"parseTime=true\" — go-sql-driver/mysql " +
				"returns DATETIME/TIMESTAMP columns as []byte without it, which breaks " +
				"every query that scans a time.Time field. Add \"?parseTime=true&loc=UTC\" " +
				"to your DSN (loc=UTC is strongly recommended since go-auth computes all " +
				"timestamps in UTC).",
		)
	}
	return nil
}

// mysqlBoolParam mirrors go-sql-driver/mysql's own DSN boolean parsing
// (readBool): "1"/"true" (case-insensitive) are true, everything else false.
func mysqlBoolParam(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true":
		return true
	default:
		return false
	}
}

func sqlDriverName(driver Driver) string {
	switch driver {
	case DriverPostgres:
		return "pgx"
	case DriverSQLite:
		return "sqlite"
	default:
		return string(driver)
	}
}
