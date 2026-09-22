package goauth

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/emailtemplate"
	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/sqldriver"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/mailer"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
)

// This file holds the phases New() runs through that have a narrow enough
// interface to stand alone: each reads the config and returns a value or an
// error, so lifting it out of New changed no ordering and no side effect.
//
// The service-construction sequence deliberately stayed in New. It is a linear
// chain of constructors with real interdependencies (sessions before two-factor
// before auth), and wrapping it would hide the wiring rather than explain it.

// applyCSRFTokenDefaults resolves the CSRF double-submit layer against the
// rest of the config: it is on unless explicitly disabled, inherits the
// session cookie's scope, and warns about the SameSite/ExposeCSRFTokenInBody
// pairing. Mutates cfg.security.CSRFToken in place; nil there means the layer is off.
func applyCSRFTokenDefaults(cfg *Config, keys keyring.Keys) {
	// The double-submit token layer is on unless explicitly disabled. A nil
	// CSRFToken means "build one with defaults", not "off" — middleware.CSRFToken
	// treats a nil config as a pass-through, so disabling is expressed by
	// leaving csrfToken nil here.
	if cfg.security.DisableCSRFToken {
		cfg.security.CSRFToken = nil
		if cfg.logger != nil {
			cfg.logger.Warn("goauth: CSRF double-submit token disabled",
				"note", "origin/referer checking still applies",
				"fix", "re-enable by removing SecurityConfig.DisableCSRFToken")
		}
	} else if cfg.security.CSRFToken == nil {
		cfg.security.CSRFToken = &middleware.CSRFTokenConfig{
			CookieName: "_csrf",
			HeaderName: "X-CSRF-Token",
			CookiePath: "/",
		}
	}
	if cfg.security.CSRFToken != nil {
		cfg.security.CSRFToken.CookieSecure = cfg.resolved.cookieSecure
		cfg.security.CSRFToken.Secret = keys.CSRF
		cfg.security.CSRFToken.Logger = cfg.logger
		// Default the token cookie's scope to the session cookie's. A
		// deployment that widened the session cookie to ".example.com" so a
		// sibling subdomain could hold a session almost certainly needs the
		// CSRF token readable there too — and a session that works while
		// every mutation 403s is the worst of the two failure modes, because
		// it looks like a permissions bug rather than a cookie-scope one.
		// An explicit CookieDomain still wins.
		if cfg.security.CSRFToken.CookieDomain == "" {
			cfg.security.CSRFToken.CookieDomain = cfg.cookie.Domain
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
			case crossSiteCookie && !cfg.security.CSRFToken.ExposeCSRFTokenInBody:
				cfg.logger.Warn("goauth: cookie SameSite=None without CSRFTokenConfig.ExposeCSRFTokenInBody — a cross-site browser frontend receives the session cookie but cannot read the CSRF token, so every state-changing request will 403")
			case !crossSiteCookie && cfg.security.CSRFToken.ExposeCSRFTokenInBody:
				cfg.logger.Warn("goauth: CSRFTokenConfig.ExposeCSRFTokenInBody without cookie SameSite=None — a cross-site browser frontend can read the CSRF token but is never sent the session cookie, so every request arrives unauthenticated",
					"same_site", cfg.cookie.SameSite)
			}
		}
	}
}

// requireDriverSupport defaults the driver to postgres and checks that the
// consumer actually blank-imported the database/sql driver the chosen
// backend needs — go-auth's own go.mod only pulls in pgx. Also enforces
// MySQL's parseTime requirement when go-auth opens the connection itself.
func requireDriverSupport(cfg *Config) error {
	if cfg.app.Database.Driver == "" {
		cfg.app.Database.Driver = DriverPostgres
	}
	switch cfg.app.Database.Driver {
	case DriverPostgres:
		// supported natively
	case DriverSQLite:
		if !sqldriver.IsRegistered("sqlite") && !sqldriver.IsRegistered("sqlite3") {
			return fmt.Errorf(
				"goauth: sqlite driver not registered — add the following import to your main package:\n\n\t_ \"modernc.org/sqlite\"",
			)
		}
	case DriverMySQL:
		if !sqldriver.IsRegistered("mysql") {
			return fmt.Errorf(
				"goauth: mysql driver not registered — add the following import to your main package:\n\n\t_ \"github.com/go-sql-driver/mysql\"",
			)
		}
		// Only checkable when go-auth opens the connection itself — a
		// consumer-provided *sql.DB is already open and its DSN is unknown.
		if cfg.app.Database.URL != "" {
			if err := sqldriver.ValidateMySQLDSN(cfg.app.Database.URL); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("goauth: unsupported driver %q", cfg.app.Database.Driver)
	}
	return nil
}

// openDatabase resolves the three ways a consumer can supply a database --
// an existing pgx pool, an existing *sql.DB, or a DSN for go-auth to open
// itself — into the one pair the rest of New needs. It records on cfg
// whether it opened anything, which is what Close later keys off.
func openDatabase(ctx context.Context, cfg *Config) (*pgxpool.Pool, *sqlstore.DB, error) {
	var pool *pgxpool.Pool
	var sqlDB *sqlstore.DB

	switch {
	case cfg.app.Database.Pool != nil:
		pool = cfg.app.Database.Pool
		rawDB := stdlib.OpenDBFromPool(pool)
		// Closing this adapter releases its resources, not the caller's pool.
		cfg.app.Database.opened = true
		sqlDB = sqlstore.NewDB(rawDB, string(DriverPostgres))
	case cfg.app.Database.DB != nil:
		if cfg.app.Database.Driver == DriverSQLite {
			if err := requireSQLiteForeignKeys(ctx, cfg.app.Database.DB); err != nil {
				return nil, nil, err
			}
		}
		sqlDB = sqlstore.NewDB(cfg.app.Database.DB, string(cfg.app.Database.Driver))
	case cfg.app.Database.URL != "":
		driverName := sqldriver.SQLName(string(cfg.app.Database.Driver))
		if cfg.app.Database.Driver == DriverSQLite {
			// sqldriver.SQLName assumes modernc.org/sqlite ("sqlite"), but the
			// registration check in requireDriverSupport also accepts mattn/go-sqlite3
			// ("sqlite3") — use whichever is actually registered so sql.Open
			// doesn't fail with "unknown driver" after registration passed.
			driverName = sqldriver.ResolveSQLiteName()
		}
		dsn := cfg.app.Database.URL
		if cfg.app.Database.Driver == DriverSQLite {
			var err error
			dsn, err = sqliteForeignKeyDSN(driverName, dsn)
			if err != nil {
				return nil, nil, err
			}
		}
		db, err := sql.Open(driverName, dsn)
		if err != nil {
			return nil, nil, fmt.Errorf("goauth: open database: %w", err)
		}
		if err := cfg.app.Database.applyConnectionLimits(db); err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, nil, fmt.Errorf("goauth: ping database: %w", err)
		}
		if cfg.app.Database.Driver == DriverSQLite {
			if err := requireSQLiteForeignKeys(ctx, db); err != nil {
				_ = db.Close()
				return nil, nil, err
			}
		}
		cfg.app.Database.opened = true
		sqlDB = sqlstore.NewDB(db, string(cfg.app.Database.Driver))
	default:
		return nil, nil, fmt.Errorf("goauth: no database pool or DSN provided")
	}

	return pool, sqlDB, nil
}

// resolveMailer picks the consumer's own Mailer over the built-in SMTP one.
// Returns nil when neither is configured — validate() has already refused
// that combination for any feature that actually sends mail.
func resolveMailer(cfg *Config) (port.Mailer, error) {
	if cfg.mailer != nil {
		return cfg.mailer, nil
	}
	if cfg.email != nil {
		smtp, err := mailer.NewSMTP(*cfg.email)
		if err != nil {
			return nil, err
		}
		return smtp, nil
	}
	// Neither configured: validate() has already refused this for any feature
	// that actually sends mail, so a nil Mailer here means nothing needs one.
	return nil, nil
}

// resolveTemplates picks the consumer's TemplateProvider over the built-in
// one. The URLValidator comes back alongside it because only the built-in
// templates have one — a custom provider builds its own links and is
// trusted to decide its own http/https policy.
func resolveTemplates(cfg *Config) (port.TemplateProvider, *port.URLValidator, error) {
	var templateProvider port.TemplateProvider
	var urlValidator *port.URLValidator
	if cfg.templates != nil {
		templateProvider = cfg.templates
	} else {
		allowHTTP := cfg.resolved.allowHTTPURLs
		urlValidator = &port.URLValidator{AllowHTTP: allowHTTP}
		p, err := emailtemplate.New(urlValidator)
		if err != nil {
			return nil, nil, err
		}
		templateProvider = p
	}
	return templateProvider, urlValidator, nil
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

// cookiesFromSession maps the service session config onto the cookie fields
// middleware writes from. Called once in New() — handlers and middleware
// receive the result at construction and never touch the service config for
// cookie names again. The two shapes stay separate by design; see
// middleware.CookieSettings.
func cookiesFromSession(cfg service.SessionConfig) middleware.CookieSettings {
	return middleware.CookieSettings{
		Name:        cfg.CookieName,
		RefreshName: cfg.RefreshCookieName,
		Domain:      cfg.Domain,
		Path:        cfg.Path,
		Secure:      cfg.Secure,
		SameSite:    cfg.SameSite,
		TTL:         cfg.Duration,
		RefreshTTL:  cfg.RefreshTTL,
	}
}

// collectOAuthProviders indexes the providers registered via WithProvider by
// name, rejecting nils, empty names and duplicates — a duplicate would
// otherwise silently win the /auth/oauth/{provider} route.
func collectOAuthProviders(cfg *Config) (map[string]port.OAuthProvider, error) {
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
	return oauthProviders, nil
}
