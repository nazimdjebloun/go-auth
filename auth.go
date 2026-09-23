// Package goauth provides authentication services and HTTP handlers.
package goauth

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/httproutes"
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
	services Services
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
}

// Services groups the configured authentication services.
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

// Services returns a copy of the configured service references. Reassigning a
// field on the returned value does not change this Auth instance's wiring.
func (a *Auth) Services() Services {
	return a.services
}

const startupDatabaseTimeout = 10 * time.Second

// New builds the Auth instance from a config produced by NewConfig(opts...)
// — the only supported way to configure go-auth. NewConfig is what runs
// validate() (required fields, secret length, origin policy, rate-limit
// settings, and everything else in config.validate()); Config's fields are
// unexported, so NewConfig is the only way to build one New() accepts.
// The validated check below is belt-and-suspenders defense in depth against
// silently proceeding with unvalidated — and in the case of an empty
// secret, cryptographically unsafe — settings.
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
	httpParts := buildHTTP(&cfg, wired)

	maintenance := newMaintenanceRunner(cfg.maintenance, collectMaintenanceTargets(wired.sessionRepo, wired.tokenRepo))
	if !cfg.maintenance.Disable {
		maintenance.start()
	}

	constructed = true
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
