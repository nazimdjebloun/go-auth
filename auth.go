package goauth

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/emailtemplate"
	"github.com/nazimdjebloun/go-auth/handler"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/internal/crypto"
	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
	"github.com/nazimdjebloun/go-auth/sqlstore"
	"github.com/nazimdjebloun/go-auth/token"
)

type Auth struct {
	Config     Config
	Pool       *pgxpool.Pool
	DB         *sqlstore.DB
	Services   Services
	Handlers   HandlerGroup
	Middleware MiddlewareGroup

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
	AuditLog  port.AuditLogRepository
}

type HandlerGroup struct {
	Register               http.HandlerFunc
	Login                  http.HandlerFunc
	AdminLogin             http.HandlerFunc
	Logout                 http.HandlerFunc
	ForgotPassword         http.HandlerFunc
	ResetPassword          http.HandlerFunc
	ChangePassword         http.HandlerFunc
	SetPasswordRequest     http.HandlerFunc
	SetPasswordConfirm     http.HandlerFunc
	VerifyEmail            http.HandlerFunc
	ResendVerification     http.HandlerFunc
	ResendVerificationPublic http.HandlerFunc
	ListSessions           http.HandlerFunc
	GetAllSessions         http.HandlerFunc
	RevokeSession          http.HandlerFunc
	RevokeManySessions     http.HandlerFunc
	RevokeAllSessions      http.HandlerFunc
	InviteRegister         http.HandlerFunc
	CheckSession           http.HandlerFunc
	RefreshToken           http.HandlerFunc
	GetMe                  http.HandlerFunc
	ChangeName             http.HandlerFunc
	DeleteAccount          http.HandlerFunc
	RequestDeleteAccount   http.HandlerFunc
	ConfirmDeleteAccount   http.HandlerFunc
	ListUsers              http.HandlerFunc
	UpdateUserRole         http.HandlerFunc
	BanUser                http.HandlerFunc
	UnbanUser              http.HandlerFunc
	DeleteUser             http.HandlerFunc
	RevokeUserSessions     http.HandlerFunc
	AdminCreateUser        http.HandlerFunc
	AdminListUserSessions  http.HandlerFunc
	AdminRevokeUserSession http.HandlerFunc
	GetUserDetail          http.HandlerFunc
	AdminListAuditLogs     http.HandlerFunc
	AdminListUserAuditLogs http.HandlerFunc
	GetInviteInfo          http.HandlerFunc
	CreateInvite           http.HandlerFunc
	ListInvites            http.HandlerFunc
	RevokeInvite           http.HandlerFunc
	ResendInvite           http.HandlerFunc
	HardDeleteInvite       http.HandlerFunc
	OAuthInitiate          http.HandlerFunc
	OAuthCallback          http.HandlerFunc
	OAuthLink              http.HandlerFunc
	OAuthUnlink            http.HandlerFunc
	OAuthProviders         http.HandlerFunc
	CSRFToken              http.HandlerFunc
	CreateOrg              http.HandlerFunc
	GetOrg                 http.HandlerFunc
	UpdateOrg              http.HandlerFunc
	DeleteOrg              http.HandlerFunc
	ListUserOrgs           http.HandlerFunc
	ListOrgMembers         http.HandlerFunc
	RemoveOrgMember        http.HandlerFunc
	UpdateOrgMemberRole    http.HandlerFunc
	LeaveOrg               http.HandlerFunc
	SetActiveOrg           http.HandlerFunc
	ClearActiveOrg         http.HandlerFunc
	CreateOrgInvite        http.HandlerFunc
	AcceptOrgInvite        http.HandlerFunc
	ListOrgInvites         http.HandlerFunc
	ResendOrgInvite        http.HandlerFunc
	DeleteOrgInvite        http.HandlerFunc
}

type MiddlewareGroup struct {
	Authenticate func(http.Handler) http.Handler
	RequireAdmin func(http.Handler) http.Handler
	RateLimit    func(http.Handler) http.Handler
	CORS         func(http.Handler) http.Handler
}

func New(config Config) (*Auth, error) {
	if config.appName == "" {
		config.appName = "App"
	}
	if config.sessionTTL == 0 {
		config.sessionTTL = 30 * 24 * time.Hour
	}
	if config.tokenTTL == 0 {
		config.tokenTTL = 1 * time.Hour
	}
	if config.refreshTokenTTL == 0 {
		config.refreshTokenTTL = 30 * 24 * time.Hour
	}
	if config.sessionIdleTTL == 0 {
		config.sessionIdleTTL = 7 * 24 * time.Hour
	}
	if config.environment.normalize() == EnvironmentDev && config.logger != nil {
		config.logger.Warn("goauth: running in dev environment — cookies are not Secure")
	}

	// Derive all cryptographic keys from the single application secret.
	keys := keyring.Derive([]byte(config.secret))

	// Auto-enable CSRF double-submit when a secret is present.
	if config.csrfToken == nil && len(config.secret) >= 32 {
		config.csrfToken = &middleware.CSRFTokenConfig{
			CookieName: "_csrf",
			HeaderName: "X-CSRF-Token",
			CookiePath: "/",
		}
	}
	if config.csrfToken != nil {
		config.csrfToken.CookieSecure = config.cookie.Secure
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
	default:
		return nil, fmt.Errorf("go-auth: unsupported driver %q", config.database.Driver)
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
		db, err := sql.Open(driverName, config.database.URL)
		if err != nil {
			return nil, fmt.Errorf("go-auth: open database: %w", err)
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, fmt.Errorf("go-auth: ping database: %w", err)
		}
		config.database.opened = true
		sqlDB = sqlstore.NewDB(db, string(config.database.Driver))
		sessRepo = sqlstore.NewSessionRepository(sqlDB)
		if config.database.Driver == DriverPostgres {
			pool, err = pgxpool.New(context.Background(), config.database.URL)
			if err != nil {
				db.Close()
				return nil, fmt.Errorf("go-auth: create connection pool: %w", err)
			}
		}
	default:
		return nil, ErrNoDatabase
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
		m, err := newSMTPMailer(*config.email)
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
		allowHTTP := config.email != nil && config.email.AllowHTTPURLs
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
		auditSvc.AddSink(audit.NewSQLAuditSink(sqlDB))
		auditSvc.AddSink(audit.NewLoggerSink(config.logger))
		for _, sink := range config.auditSinks {
			auditSvc.AddSink(sink)
		}
		auditSvc.Start(context.Background())
		auditPub = auditSvc
	}

	serviceCfg := service.Config{
		AppName:                    config.appName,
		BaseURL:                    config.baseURL,
		InviteOnly:                 !config.registration.AllowPublic,
		EnableEmailPassword:        config.registration.EnableEmailPassword,
		EnableOAuth:                config.registration.EnableOAuth,
		EnableInvite:               config.registration.EnableInvite,
		RequireEmailVerification:   config.registration.RequireEmailVerification,
		InviteTTL:                  config.registration.InviteTTL,
		VerificationCodeTTL:        config.registration.VerificationCodeTTL,
		VerificationResendInterval: config.verificationResendInterval,
		SessionTTL:               config.sessionTTL,
		TokenTTL:                 config.tokenTTL,
		PasswordPolicy:           config.passwordPolicy,
		TemplateProvider:         templateProvider,
		URLValidator:             urlValidator,
		Logger:                   config.logger,
		Audit:                    auditPub,
	}

	sessionCfg := service.DefaultSessionConfig()
	sessionCfg.Duration = config.sessionTTL
	sessionCfg.IdleTTL = config.sessionIdleTTL
	sessionCfg.RefreshTTL = config.refreshTokenTTL
	sessionCfg.MaxLifetime = config.maxLifetime
	sessionCfg.GraceWindow = config.graceWindow
	sessionCfg.TouchDebounce = config.touchDebounce
	sessionCfg.CookieName = config.cookie.Name
	sessionCfg.Domain = config.cookie.Domain
	sessionCfg.Path = config.cookie.Path
	sessionCfg.Secure = config.cookie.Secure
	sessionCfg.SameSite = int(config.cookie.SameSite)
	sessionCfg.Logger = config.logger
	sessionCfg.Audit = auditPub

	sessSvc := service.NewSessionService(sessRepo, genImpl, sessionCfg)

	verifySvc := service.NewVerificationService(userRepo, tokenRepo, genImpl, mailer, serviceCfg)
	authSvc := service.NewAuthService(userRepo, sessionRepoSQL, tokenRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc, verifySvc)
	passSvc := service.NewPasswordService(userRepo, tokenRepo, hasherImpl, genImpl, mailer, sessionRepoSQL, serviceCfg)
	inviteSvc := service.NewInviteService(userRepo, sessionRepoSQL, inviteRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc)
	adminSvc := service.NewAdminService(userRepo, sessionRepoSQL, providerAccountRepo, hasherImpl, serviceCfg, sessSvc)

	// Attach logger to session repository
	if config.logger != nil {
		sessionRepoSQL.WithLogger(config.logger)
	}

	// Build OAuth providers from registered WithProvider calls
	oauthProviders := make(map[string]port.OAuthProvider)
	for _, p := range config.providers {
		if p == nil {
			return nil, fmt.Errorf("go-auth: nil provider registered via WithProvider")
		}
		name := p.Name()
		if name == "" {
			return nil, fmt.Errorf("go-auth: provider with empty name registered via WithProvider")
		}
		if _, exists := oauthProviders[name]; exists {
			return nil, fmt.Errorf("go-auth: duplicate provider %q", name)
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
			AppName:                  config.appName,
			BaseURL:                  config.baseURL,
			SessionTTL:               config.sessionTTL,
			TokenTTL:                 config.tokenTTL,
			CookieName:               config.cookie.Name,
			CookieDomain:             config.cookie.Domain,
			CookiePath:               config.cookie.Path,
			CookieSecure:             config.cookie.Secure,
			CookieSameSite:           config.cookie.SameSite,
			RequireEmailVerification: config.registration.RequireEmailVerification,
			EnableOAuth:              config.registration.EnableOAuth,
			InviteOnly:               !config.registration.AllowPublic,
			Logger:                   config.logger,
			Audit:                    auditPub,
			Encryptor:                encryptor,
		}
		oauthSvc = service.NewOAuthService(oauthProviders, providerAccountRepo, userRepo, tokenRepo, hasherImpl, genImpl, sessSvc, verifySvc, oauthCfg)
	}

	var orgSvc *service.OrgService
	var orgInviteSvc *service.OrgInviteService
	if config.organizations.Enable {
		orgRepo := sqlstore.NewOrgRepository(sqlDB)
		orgInviteRepo := sqlstore.NewOrgInviteRepository(sqlDB)
		orgSvc = service.NewOrgService(orgRepo, userRepo, sessRepo, sqlDB, service.OrgServiceConfig{
			MaxOrgsPerUser: config.organizations.MaxOrgsPerUser,
			Logger:         config.logger,
			Audit:          auditPub,
		})
		orgInviteSvc = service.NewOrgInviteService(orgInviteRepo, orgRepo, userRepo, sqlDB, genImpl, mailer, service.OrgInviteServiceConfig{
			MaxOrgsPerUser:  config.organizations.MaxOrgsPerUser,
			InviteTTL:       inviteTTLForOrgs(config),
			BaseURL:         config.baseURL,
			AppName:         config.appName,
			TemplateProvider: templateProvider,
			URLValidator:     urlValidator,
			Logger:          config.logger,
			Audit:           auditPub,
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
	}
	rateLimitMW := middleware.RateLimit(config.rateLimit)
	csrfMW := middleware.OriginCheck(config.allowedOrigins, config.allowMissingCSRFHeaders, trustedIPs, config.logger)
	csrfTokenMW := middleware.CSRFToken(config.csrfToken)
	corsMW := middleware.CORS(config.allowedOrigins)

	return &Auth{
		Config:          config,
		Pool:            pool,
		DB:              sqlDB,
		authService:     authSvc,
		passwordService: passSvc,
		sessionService:  sessSvc,
		verifyService:   verifySvc,
		inviteService:   inviteSvc,
		adminService:    adminSvc,
		oAuthService:    oauthSvc,
		orgService:       orgSvc,
		orgInviteService: orgInviteSvc,
		auditService:     auditSvc,
		auditLogRepo:     auditLogRepo,
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
			GetInviteInfo:            corsMW(http.HandlerFunc(h.GetInviteInfo)).ServeHTTP,
			GetMe:                    corsMW(authMW(http.HandlerFunc(h.GetMe))).ServeHTTP,
			CheckSession:             corsMW(http.HandlerFunc(h.CheckAuth)).ServeHTTP,
			RefreshToken:             corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.RefreshToken))))).ServeHTTP,
			ChangeName:               corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ChangeName))))).ServeHTTP,
			DeleteAccount:            corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.DeleteAccount))))).ServeHTTP,
			RequestDeleteAccount:     corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RequestDeleteAccount)))))).ServeHTTP,
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
			CreateOrg:              corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.CreateOrg)))))).ServeHTTP,
			GetOrg:                 corsMW(authMW(http.HandlerFunc(h.GetOrg))).ServeHTTP,
			UpdateOrg:              corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.UpdateOrg))))).ServeHTTP,
			DeleteOrg:              corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.DeleteOrg))))).ServeHTTP,
			ListUserOrgs:           corsMW(authMW(http.HandlerFunc(h.ListUserOrgs))).ServeHTTP,
			ListOrgMembers:         corsMW(authMW(http.HandlerFunc(h.ListOrgMembers))).ServeHTTP,
			RemoveOrgMember:        corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RemoveMember))))).ServeHTTP,
			UpdateOrgMemberRole:    corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.UpdateMemberRole))))).ServeHTTP,
			LeaveOrg:               corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.LeaveOrg))))).ServeHTTP,
			SetActiveOrg:           corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.SetActiveOrg))))).ServeHTTP,
			ClearActiveOrg:         corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ClearActiveOrg))))).ServeHTTP,
			CreateOrgInvite:        corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.CreateOrgInvite)))))).ServeHTTP,
			AcceptOrgInvite:        corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.AcceptOrgInvite))))).ServeHTTP,
			ListOrgInvites:         corsMW(authMW(http.HandlerFunc(h.ListOrgInvites))).ServeHTTP,
			ResendOrgInvite:        corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ResendOrgInvite))))).ServeHTTP,
			DeleteOrgInvite:        corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.DeleteOrgInvite))))).ServeHTTP,
		},
		Middleware: MiddlewareGroup{
			Authenticate: authMW,
			RequireAdmin: adminMW,
			RateLimit:    rateLimitMW,
			CORS:         corsMW,
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
	if a.Pool != nil {
		a.Pool.Close()
	}
	if a.Config.database.opened && a.DB != nil {
		a.DB.Close()
	}
}

func (a *Auth) Mount(mux *http.ServeMux) {
	// All middleware (CORS, rate limit, csrf token, origin check, auth, admin)
	// is already baked into a.Handlers — CORS outermost so preflight OPTIONS
	// short-circuits before rate limiting. Mount only registers routes; do NOT
	// wrap the mux again with a.Middleware.CORS or any other middleware.
	//
	// handle registers a route and, when CORS origins are configured, also the
	// exact OPTIONS twin for the same path. OPTIONS is registered 1:1 with each
	// route go-auth owns — never a catch-all — so preflight requests for paths
	// go-auth does not own (including a consumer's own routes on a shared mux)
	// still get a normal 404/405 and never reach the CORS layer.
	preflight := len(a.Config.allowedOrigins) > 0
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

	if a.Config.registration.EnableEmailPassword {
		handle("POST /auth/register", a.Handlers.Register)
		handle("POST /auth/signup", a.Handlers.Register)
	}
	handle("POST /auth/login", a.Handlers.Login)
	handle("POST /auth/signin", a.Handlers.Login)
	handle("POST /auth/admin/login", a.Handlers.AdminLogin)
	handle("POST /auth/forgot-password", a.Handlers.ForgotPassword)
	handle("POST /auth/reset-password", a.Handlers.ResetPassword)
	handle("POST /auth/verify-email", a.Handlers.VerifyEmail)
	if a.Config.registration.EnableInvite {
		handle("GET /auth/invite/info", a.Handlers.GetInviteInfo)
		handle("POST /auth/invite/register", a.Handlers.InviteRegister)
	}
	handle("POST /auth/logout", a.Handlers.Logout)
	handle("POST /auth/signout", a.Handlers.Logout)
	handle("GET /auth/me", a.Handlers.GetMe)
	handle("GET /auth/check", a.Handlers.CheckSession)
	handle("GET /auth/csrf-token", a.Handlers.CSRFToken)
	handle("PUT /auth/name", a.Handlers.ChangeName)
	handle("GET /auth/sessions", a.Handlers.ListSessions)
	handle("GET /auth/sessions/all", a.Handlers.GetAllSessions)
	handle("DELETE /auth/sessions/{id}", a.Handlers.RevokeSession)
	handle("POST /auth/sessions/revoke", a.Handlers.RevokeManySessions)
	handle("DELETE /auth/sessions", a.Handlers.RevokeAllSessions)
	handle("PUT /auth/password", a.Handlers.ChangePassword)
	handle("POST /auth/change-password", a.Handlers.ChangePassword)
	handle("POST /auth/set-password/request", a.Handlers.SetPasswordRequest)
	handle("POST /auth/set-password/confirm", a.Handlers.SetPasswordConfirm)
	handle("DELETE /auth/account", a.Handlers.DeleteAccount)
	handle("POST /auth/account/delete/request", a.Handlers.RequestDeleteAccount)
	handle("POST /auth/account/delete/confirm", a.Handlers.ConfirmDeleteAccount)
	handle("POST /auth/resend-verification", a.Handlers.ResendVerification)
	handle("POST /auth/verify-email/resend", a.Handlers.ResendVerificationPublic)
	handle("POST /auth/refresh", a.Handlers.RefreshToken)
	handle("GET /admin/users", a.Handlers.ListUsers)
	handle("GET /admin/users/{id}", a.Handlers.GetUserDetail)
	handle("PATCH /admin/users/{id}/role", a.Handlers.UpdateUserRole)
	handle("PATCH /admin/users/{id}/ban", a.Handlers.BanUser)
	handle("PATCH /admin/users/{id}/unban", a.Handlers.UnbanUser)
	handle("DELETE /admin/users/{id}", a.Handlers.DeleteUser)
	handle("POST /admin/users", a.Handlers.AdminCreateUser)
	handle("GET /admin/users/{id}/sessions", a.Handlers.AdminListUserSessions)
	handle("DELETE /admin/users/{id}/sessions/{sessionId}", a.Handlers.AdminRevokeUserSession)
	handle("DELETE /admin/users/{id}/sessions", a.Handlers.RevokeUserSessions)
	handle("GET /admin/audit-logs", a.Handlers.AdminListAuditLogs)
	handle("GET /admin/users/{id}/audit-logs", a.Handlers.AdminListUserAuditLogs)
	if a.Config.registration.EnableInvite {
		handle("POST /admin/invites", a.Handlers.CreateInvite)
		handle("GET /admin/invites", a.Handlers.ListInvites)
		handle("DELETE /admin/invites/{id}", a.Handlers.RevokeInvite)
		handle("POST /admin/invites/{id}/resend", a.Handlers.ResendInvite)
		handle("DELETE /admin/invites/{id}/hard", a.Handlers.HardDeleteInvite)
	}
	if a.Config.registration.EnableOAuth && a.oAuthService != nil {
		handle("GET /auth/oauth/{provider}", a.Handlers.OAuthInitiate)
		handle("GET /auth/oauth/{provider}/callback", a.Handlers.OAuthCallback)
		handle("POST /auth/oauth/{provider}/callback", a.Handlers.OAuthCallback)
		handle("POST /auth/oauth/{provider}/link", a.Handlers.OAuthLink)
		handle("POST /auth/oauth/{provider}/unlink", a.Handlers.OAuthUnlink)
		handle("GET /auth/oauth/providers", a.Handlers.OAuthProviders)
	}
	if a.orgService != nil {
		handle("POST /auth/orgs", a.Handlers.CreateOrg)
		handle("GET /auth/orgs", a.Handlers.ListUserOrgs)
		handle("GET /auth/orgs/{orgID}", a.Handlers.GetOrg)
		handle("PUT /auth/orgs/{orgID}", a.Handlers.UpdateOrg)
		handle("DELETE /auth/orgs/{orgID}", a.Handlers.DeleteOrg)
		handle("GET /auth/orgs/{orgID}/members", a.Handlers.ListOrgMembers)
		handle("DELETE /auth/orgs/{orgID}/members/{userID}", a.Handlers.RemoveOrgMember)
		handle("PATCH /auth/orgs/{orgID}/members/{userID}/role", a.Handlers.UpdateOrgMemberRole)
		handle("POST /auth/orgs/{orgID}/leave", a.Handlers.LeaveOrg)
		handle("PUT /auth/orgs/active", a.Handlers.SetActiveOrg)
		handle("DELETE /auth/orgs/active", a.Handlers.ClearActiveOrg)
		handle("POST /auth/orgs/{orgID}/invites", a.Handlers.CreateOrgInvite)
		handle("POST /auth/orgs/invites/accept", a.Handlers.AcceptOrgInvite)
		handle("GET /auth/orgs/{orgID}/invites", a.Handlers.ListOrgInvites)
		handle("POST /auth/orgs/{orgID}/invites/{inviteID}/resend", a.Handlers.ResendOrgInvite)
		handle("DELETE /auth/orgs/{orgID}/invites/{inviteID}", a.Handlers.DeleteOrgInvite)
	}
}

func (a *Auth) Register(ctx context.Context, input RegisterInput) (*RegisterResult, *domain.AuthError) {
	result, err := a.authService.Register(ctx, service.RegisterInput{
		Email:    input.Email,
		Password: input.Password,
		Name:     input.Name,
	})
	if err != nil {
		return nil, err
	}
	return &RegisterResult{
		User:                 result.User,
		Session:              result.Session,
		SessionToken:         result.SessionToken,
		RefreshToken:         result.RefreshToken,
		RequiresVerification: result.RequiresVerification,
	}, nil
}

func (a *Auth) Login(ctx context.Context, input LoginInput) (*LoginResult, *domain.AuthError) {
	result, err := a.authService.Login(ctx, service.LoginInput{
		Email:     input.Email,
		Password:  input.Password,
		IP:        input.IP,
		UserAgent: input.UserAgent,
	})
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		User:                 result.User,
		Session:              result.Session,
		SessionToken:         result.SessionToken,
		RefreshToken:         result.RefreshToken,
		RequiresVerification: result.RequiresVerification,
	}, nil
}

func (a *Auth) CompleteInviteRegistration(ctx context.Context, input CompleteInviteInput) (*CompleteInviteResult, *domain.AuthError) {
	result, err := a.inviteService.CompleteInviteRegistration(ctx, service.CompleteInviteInput{
		Code:            input.Code,
		Name:            input.Name,
		Password:        input.Password,
		ConfirmPassword: input.ConfirmPassword,
	})
	if err != nil {
		return nil, err
	}
	return &CompleteInviteResult{
		User:         result.User,
		Session:      result.Session,
		SessionToken: result.SessionToken,
		RefreshToken: result.RefreshToken,
	}, nil
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

func inviteTTLForOrgs(cfg Config) time.Duration {
	if cfg.organizations.InviteTTL > 0 {
		return cfg.organizations.InviteTTL
	}
	return 7 * 24 * time.Hour
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
