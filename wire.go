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
// pairing. Mutates cfg.csrfToken in place; nil there means the layer is off.
func applyCSRFTokenDefaults(cfg *Config, keys keyring.Keys) {
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
}

// requireDriverSupport defaults the driver to postgres and checks that the
// consumer actually blank-imported the database/sql driver the chosen
// backend needs — go-auth's own go.mod only pulls in pgx. Also enforces
// MySQL's parseTime requirement when go-auth opens the connection itself.
func requireDriverSupport(cfg *Config) error {
	if cfg.database.Driver == "" {
		cfg.database.Driver = DriverPostgres
	}
	switch cfg.database.Driver {
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
		if cfg.database.URL != "" {
			if err := sqldriver.ValidateMySQLDSN(cfg.database.URL); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("goauth: unsupported driver %q", cfg.database.Driver)
	}
	return nil
}

// openDatabase resolves the three ways a consumer can supply a database --
// an existing pgx pool, an existing *sql.DB, or a DSN for go-auth to open
// itself — into the one pair the rest of New needs. It records on cfg
// whether it opened anything, which is what Close later keys off.
func openDatabase(cfg *Config) (*pgxpool.Pool, *sqlstore.DB, error) {
	var pool *pgxpool.Pool
	var sqlDB *sqlstore.DB

	switch {
	case cfg.database.Pool != nil:
		pool = cfg.database.Pool
		rawDB := stdlib.OpenDBFromPool(pool)
		sqlDB = sqlstore.NewDB(rawDB, string(DriverPostgres))
	case cfg.database.DB != nil:
		sqlDB = sqlstore.NewDB(cfg.database.DB, string(cfg.database.Driver))
	case cfg.database.URL != "":
		driverName := sqldriver.SQLName(string(cfg.database.Driver))
		if cfg.database.Driver == DriverSQLite {
			// sqldriver.SQLName assumes modernc.org/sqlite ("sqlite"), but the
			// registration check in requireDriverSupport also accepts mattn/go-sqlite3
			// ("sqlite3") — use whichever is actually registered so sql.Open
			// doesn't fail with "unknown driver" after registration passed.
			driverName = sqldriver.ResolveSQLiteName()
		}
		db, err := sql.Open(driverName, cfg.database.URL)
		if err != nil {
			return nil, nil, fmt.Errorf("goauth: open database: %w", err)
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("goauth: ping database: %w", err)
		}
		cfg.database.opened = true
		sqlDB = sqlstore.NewDB(db, string(cfg.database.Driver))
		if cfg.database.Driver == DriverPostgres {
			pool, err = pgxpool.New(context.Background(), cfg.database.URL)
			if err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("goauth: create connection pool: %w", err)
			}
			cfg.database.poolOpened = true
		}
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
	if cfg.templateProvider != nil {
		templateProvider = cfg.templateProvider
	} else {
		allowHTTP := cfg.allowHTTPURLs
		urlValidator = &port.URLValidator{AllowHTTP: allowHTTP}
		p, err := emailtemplate.New(urlValidator)
		if err != nil {
			return nil, nil, err
		}
		templateProvider = p
	}
	return templateProvider, urlValidator, nil
}

// startAuditService builds and starts the audit pipeline when it is enabled,
// wiring the built-in SQL and logger sinks ahead of any the consumer added.
// Both return values are nil when auditing is off, which every caller
// treats as "do not publish".
func startAuditService(cfg *Config, sqlDB *sqlstore.DB) (*audit.AuditService, service.AuditPublisher) {
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
	return auditSvc, auditPub
}

// buildSessionConfig maps the public SessionConfig/CookieConfig fields onto
// the service layer's own shape. It reads cfg.cookieSecure, never
// cfg.cookie.Secure — the former is the value applyDefaults resolved, the
// latter is unresolved consumer intent.
func buildSessionConfig(cfg *Config, auditPub service.AuditPublisher) service.SessionConfig {
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
	return sessionCfg
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
