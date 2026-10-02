// Package goauth provides authentication services and HTTP handlers.
package goauth

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/httproutes"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// Auth is a configured go-auth instance.
type Auth struct {
	cfg      Config
	pool     *pgxpool.Pool
	db       *sqlstore.DB
	services serviceSet
	routes   []httproutes.Entry

	// cookies is the resolved session/refresh cookie scope, built once in
	// New() via cookiesFromSession. Facade helpers and all wiring read it —
	// nothing pulls cookie names off the session service at request time.
	cookies middleware.CookieSettings

	authMW      func(http.Handler) http.Handler
	adminMW     func(http.Handler) http.Handler
	rateLimitMW func(http.Handler) http.Handler
	corsMW      func(http.Handler) http.Handler
	orgMemberMW func(http.Handler) http.Handler

	auditService *audit.Service

	// twoFactorStore is always library-constructed (see New), so unlike the
	// rate-limit Store it is unconditionally ours to close.
	twoFactorStore ratelimit.Store
	maintenance    *maintenanceRunner
	recoveryWorker *service.RecoveryWorker
}

// serviceSet keeps the concrete instances needed by internal HTTP wiring.
// The public Services value exposes their operation methods through interfaces.
type serviceSet struct {
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

// Services returns a copy of the configured programmatic capabilities.
// Reassigning a field on the returned value does not change this Auth instance.
// Optional capabilities remain nil when their features are unavailable.
func (a *Auth) Services() Services {
	s := Services{
		Auth: a.services.Auth, Password: a.services.Password,
		Session: a.services.Session, Verify: a.services.Verify,
		Invite: a.services.Invite, Admin: a.services.Admin,
		TwoFactor: a.services.TwoFactor, AuditLog: a.services.AuditLog,
	}
	if a.services.OAuth != nil {
		s.OAuth = a.services.OAuth
	}
	if a.services.Org != nil {
		s.Org = a.services.Org
	}
	if a.services.OrgInvite != nil {
		s.OrgInvite = a.services.OrgInvite
	}
	return s
}

const startupDatabaseTimeout = 10 * time.Second

// New builds the Auth instance from a config produced by NewConfig(opts...)
// — the only supported way to configure go-auth. New clones the configuration,
// resolves defaults, and validates all settings again before deriving keys or
// initializing services, including options applied after NewConfig.
func New(in *Config) (*Auth, error) {
	cfg, keys, err := prepareConfig(in)
	if err != nil {
		return nil, err
	}
	passwordHasher, passwordPepperKeys, err := buildPasswordHasher(&cfg)
	if err != nil {
		return nil, err
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
	wired, err := buildServices(startupCtx, &cfg, keys, sqlDB, passwordHasher, passwordPepperKeys, hasherImpl)
	if err != nil {
		return nil, err
	}
	// Allocate owned rate-limit resources only after every fallible startup
	// step succeeds. A reusable Config carries no library-owned store.
	if cfg.rateLimit.Enabled && cfg.rateLimit.Store == nil {
		cfg.rateLimit.Store = ratelimit.NewMemoryStore(ratelimit.WithStoreLogger(cfg.logger))
	}
	httpParts := buildHTTP(&cfg, wired)

	maintenance := newMaintenanceRunner(cfg.maintenance, collectMaintenanceTargets(wired.sessionRepo, wired.tokenRepo))
	if !cfg.maintenance.Disable {
		maintenance.start()
	}

	constructed = true
	if wired.recoveryWorker != nil {
		wired.recoveryWorker.Start(context.Background())
	}
	return &Auth{
		cfg:            cfg,
		pool:           pool,
		db:             sqlDB,
		cookies:        wired.cookies,
		authMW:         httpParts.authMW,
		adminMW:        httpParts.adminMW,
		rateLimitMW:    httpParts.rateLimitMW,
		corsMW:         httpParts.corsMW,
		orgMemberMW:    httpParts.orgMemberMW,
		auditService:   wired.auditService,
		twoFactorStore: wired.twoFactorStore,
		maintenance:    maintenance,
		recoveryWorker: wired.recoveryWorker,
		services:       wired.services,
		routes:         httpParts.routes,
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

// Close stops background work and closes owned resources.
func (a *Auth) Close() {
	if a.recoveryWorker != nil {
		a.recoveryWorker.Stop()
	}
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
		if err := a.db.Close(); err != nil && a.cfg.logger != nil {
			a.cfg.logger.Error("goauth: close database", "err", err)
		}
	}
}
