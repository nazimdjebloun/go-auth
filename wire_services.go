package goauth

import (
	"context"
	"fmt"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/crypto"
	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/nazimdjebloun/go-auth/token"
)

// serviceWiring contains the values New needs after constructing services.
// Repositories and stores retain their original ownership rules.
type serviceWiring struct {
	services       serviceSet
	sessionRepo    *sqlstore.SessionRepository
	tokenRepo      *sqlstore.TokenRepository
	userRepo       *sqlstore.UserRepository
	orgRepo        port.OrgRepository
	cookies        middleware.CookieSettings
	auditService   *audit.Service
	twoFactorStore ratelimit.Store
	recoveryWorker *service.RecoveryWorker
}

// buildServices keeps the order of repository, audit, and service construction
// explicit. It runs after opening the database and before HTTP wiring.
func buildServices(startupCtx context.Context, cfg *Config, keys keyring.Keys, sqlDB *sqlstore.DB, passwordHasher *service.PasswordHasher, passwordPepperKeys map[uint32][]byte, hasherImpl port.Hasher) (serviceWiring, error) {
	sessionRepo := sqlstore.NewSessionRepository(sqlDB)
	if cfg.logger != nil {
		sessionRepo.WithLogger(cfg.logger)
	}

	userRepo := sqlstore.NewUserRepository(sqlDB)
	if cfg.appPermissions.Enable {
		userRepo.WithAppPermissions()
	}
	// Keep the zero-config path lazy: historically New with a borrowed pgx
	// pool did not dial it. Once any pepper key is configured, validate every
	// version present in the database before serving requests. Omitting the
	// option against an already-peppered database still fails closed per-row at
	// login; it never falls back to treating a peppered hash as unpeppered.
	if len(passwordPepperKeys) > 0 {
		storedPepperVersions, err := userRepo.ListPasswordPepperVersions(startupCtx)
		if err != nil {
			return serviceWiring{}, fmt.Errorf("goauth: validating stored password pepper versions: %w", err)
		}
		if err := passwordHasher.ValidateStoredVersions(storedPepperVersions); err != nil {
			return serviceWiring{}, fmt.Errorf("goauth: invalid password pepper configuration: %w", err)
		}
	}
	tokenRepo := sqlstore.NewTokenRepository(sqlDB)
	inviteRepo := sqlstore.NewInviteRepository(sqlDB)
	providerAccountRepo := sqlstore.NewProviderAccountRepository(sqlDB)
	if keys.OAuthEnc != nil {
		enc, err := crypto.NewEncryptor(keys.OAuthEnc)
		if err != nil {
			return serviceWiring{}, fmt.Errorf("goauth: oauth encryptor: %w", err)
		}
		providerAccountRepo.WithDecryptor(enc.Decrypt)
	}
	auditLogRepo := sqlstore.NewAuditLogRepository(sqlDB)

	genImpl := token.New()

	mailer, err := resolveMailer(cfg)
	if err != nil {
		return serviceWiring{}, err
	}

	templateProvider, urlValidator, err := resolveTemplates(cfg)
	if err != nil {
		return serviceWiring{}, err
	}

	oauthProviders, err := collectOAuthProviders(cfg)
	if err != nil {
		return serviceWiring{}, err
	}

	auditSvc, auditPub, err := startAuditService(cfg, sqlDB)
	if err != nil {
		return serviceWiring{}, err
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

	sessionCfg := buildSessionConfig(cfg, auditPub)
	cookies := cookiesFromSession(sessionCfg)

	// Direct session API calls must get the same record-iff-commit guarantee
	// as login: the session mutation and its audit record share one tx.
	sessSvc := service.NewSessionService(sqlDB, sessionRepo, genImpl, sessionCfg)
	var appPermissionsSvc *service.AppPermissionsService
	if cfg.appPermissions.Enable {
		appRepo := sqlstore.NewAppPermissionsRepository(sqlDB)
		appPermissionsSvc = service.NewAppPermissionsService(sqlDB, userRepo, sessionRepo, sessSvc, appRepo, appRepo, appRepo, appRepo, service.AppPermissionsServiceConfig{DefaultRoleSlug: cfg.appPermissions.DefaultRoleSlug, RequireAdminTwoFactor: !cfg.twoFactor.DisableAdminTwoFactor || cfg.twoFactor.RequireEmail2FA, Audit: auditPub})
	}

	verifySvc := service.NewVerificationService(userRepo, tokenRepo, genImpl, mailer, sqlDB, serviceCfg)
	serviceCfg.AppPermissions = appPermissionsSvc

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
	twoFactorSvc := service.NewTwoFactorService(sqlDB, userRepo, sessionRepo, tokenRepo, hasherImpl, mailer, twoFactorStore, serviceCfg, sessSvc)

	// Register commits the user row and its audit record in one
	// transaction, so a crash cannot leave an account with no record of its
	// registration (record-iff-commit).
	authSvc := service.NewAuthService(sqlDB, userRepo, sessionRepo, tokenRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc, verifySvc, twoFactorSvc)
	passSvc := service.NewPasswordService(userRepo, tokenRepo, hasherImpl, genImpl, mailer, sessionRepo, sqlDB, serviceCfg)
	var recoveryWorker *service.RecoveryWorker
	if mailer != nil {
		recoveryWorker = service.NewRecoveryWorker(sqlstore.NewRecoveryRepository(sqlDB), passSvc, verifySvc, cfg.logger)
	}
	inviteSvc := service.NewInviteService(userRepo, sessionRepo, inviteRepo, hasherImpl, genImpl, mailer, sqlDB, serviceCfg, sessSvc, twoFactorSvc)
	// Unbanning must commit its audit record with the state change; bans and
	// role changes already get that from the admin guard's own transaction.
	adminSvc := service.NewAdminService(sqlDB, userRepo, sessionRepo, providerAccountRepo, auditLogRepo, hasherImpl, serviceCfg, sessSvc)

	var oauthSvc *service.OAuthService
	if len(oauthProviders) > 0 {
		var encryptor *crypto.Encryptor
		if keys.OAuthEnc != nil {
			encryptor, err = crypto.NewEncryptor(keys.OAuthEnc)
			if err != nil {
				return serviceWiring{}, fmt.Errorf("goauth: oauth encryptor: %w", err)
			}
		}
		oauthCfg := service.OAuthServiceConfig{
			AppPermissions:           appPermissionsSvc,
			CommonConfig:             commonCfg,
			RequireEmailVerification: cfg.registration.RequireEmailVerification,
			EnableOAuth:              cfg.registration.EnableOAuth,
			InviteOnly:               !cfg.registration.AllowPublic,
			Encryptor:                encryptor,
			DisableAdminTwoFactor:    cfg.twoFactor.DisableAdminTwoFactor,
		}
		oauthSvc = service.NewOAuthService(oauthProviders, providerAccountRepo, userRepo, tokenRepo, hasherImpl, genImpl, sessSvc, verifySvc, sqlDB, oauthCfg)
		oauthSvc.AttachTwoFactor(twoFactorSvc)
	}

	var orgSvc *service.OrgService
	var orgInviteSvc *service.OrgInviteService
	var orgRepo port.OrgRepository
	if cfg.organizations.Enable {
		orgRepo = sqlstore.NewOrgRepository(sqlDB)
		orgInviteRepo := sqlstore.NewOrgInviteRepository(sqlDB)
		orgSvc = service.NewOrgService(orgRepo, userRepo, sessionRepo, sqlDB, service.OrgServiceConfig{
			AppPermissions: appPermissionsSvc,
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

	return serviceWiring{
		services: serviceSet{
			Auth: authSvc, Password: passSvc, Session: sessSvc,
			Verify: verifySvc, Invite: inviteSvc, Admin: adminSvc,
			OAuth: oauthSvc, Org: orgSvc, OrgInvite: orgInviteSvc,
			TwoFactor: twoFactorSvc, AuditLog: auditLogRepo,
			AppPermissions: appPermissionsSvc,
		},
		sessionRepo: sessionRepo, tokenRepo: tokenRepo, userRepo: userRepo,
		orgRepo: orgRepo, cookies: cookies, auditService: auditSvc,
		twoFactorStore: twoFactorStore,
		recoveryWorker: recoveryWorker,
	}, nil
}

// startAuditService builds and starts the durable audit pipeline when it is
// enabled. The record store writes audit_log rows in the caller's
// transaction; external delivery sinks are fed from the audit_outbox table
// by the dispatcher. Both return values are nil when auditing is off, which
// every caller treats as "do not record".
func startAuditService(cfg *Config, sqlDB *sqlstore.DB) (*audit.Service, service.AuditPublisher, error) {
	if !cfg.audit.Enabled {
		return nil, nil, nil
	}

	auditCfg := audit.ServiceConfig{
		FailureMode:        cfg.audit.FailureMode,
		Workers:            cfg.audit.Workers,
		BatchSize:          cfg.audit.BatchSize,
		FlushInterval:      cfg.audit.FlushInterval,
		RetentionDays:      cfg.audit.RetentionDays,
		EnqueueFailureMode: cfg.audit.EnqueueFailureMode,
		MaxAttempts:        cfg.audit.MaxAttempts,
		ClaimLease:         cfg.audit.ClaimLease,
		OutboxMaxAge:       cfg.audit.OutboxMaxAge,
		DeadLetterTTL:      cfg.audit.DeadLetterTTL,
		OutboxMaxRows:      cfg.audit.OutboxMaxRows,
	}

	deliverySinks := append(append([]audit.EventSink(nil), cfg.audit.Sinks...), cfg.auditSinks...)
	hasDeliverySinks := len(deliverySinks) > 0
	var outbox audit.OutboxStore
	if hasDeliverySinks {
		// Reject an unsafe lease or an unbounded sink before constructing
		// the write path. Continuing without an outbox would make Record
		// dereference a nil store and, worse, advertise delivery that can
		// never happen.
		if err := audit.ValidateConfig(auditCfg, deliverySinks...); err != nil {
			return nil, nil, fmt.Errorf("goauth: invalid audit delivery configuration: %w", err)
		}
		outbox = sqlstore.NewOutboxRepository(sqlDB)
	}

	auditSvc := audit.NewService(
		auditCfg,
		sqlDB,
		sqlstore.NewRecordRepository(sqlDB),
		outbox,
		cfg.logger,
	)
	auditSvc.AddInlineSink(audit.NewLoggerSink(cfg.logger))
	for _, sink := range deliverySinks {
		auditSvc.AddSink(sink)
	}
	if err := auditSvc.Start(context.Background()); err != nil {
		return nil, nil, fmt.Errorf("goauth: start audit service: %w", err)
	}
	return auditSvc, auditSvc, nil
}

// buildSessionConfig maps the public SessionConfig/CookieConfig fields onto
// the service layer's own shape. It reads cfg.resolved.cookieSecure, never
// cfg.cookie.Secure — the former is the value applyDefaults resolved, the
// latter is unresolved consumer intent.
func buildSessionConfig(cfg *Config, auditPub service.AuditPublisher) service.SessionConfig {
	sessionCfg := service.DefaultSessionConfig()
	sessionCfg.Duration = cfg.session.TTL
	sessionCfg.IdleTTL = cfg.session.IdleTTL
	sessionCfg.RefreshTTL = cfg.session.RefreshTokenTTL
	sessionCfg.MaxLifetime = cfg.session.MaxLifetime
	sessionCfg.GraceWindow = cfg.resolved.graceWindow
	sessionCfg.TouchDebounce = cfg.resolved.touchDebounce
	sessionCfg.CookieName = cfg.cookie.Name
	sessionCfg.RefreshCookieName = cfg.cookie.RefreshName
	sessionCfg.Domain = cfg.cookie.Domain
	sessionCfg.Path = cfg.cookie.Path
	sessionCfg.Secure = cfg.resolved.cookieSecure
	sessionCfg.SameSite = cfg.cookie.SameSite
	sessionCfg.Logger = cfg.logger
	sessionCfg.Audit = auditPub
	return sessionCfg
}
