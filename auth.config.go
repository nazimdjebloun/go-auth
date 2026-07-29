package goauth

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

type Driver string

const (
	DriverPostgres Driver = "postgres"
	DriverSQLite   Driver = "sqlite3"
	DriverMySQL    Driver = "mysql"
)

const bcryptCost = 12
const tokenLength = 32

// ─── Config sub-types ───────────────────────────────────────

// DatabaseConfig configures the database connection.
// Provide one of URL, DB, or Pool. URL is the preferred option —
// the library will open, validate, and close the connection automatically.
type DatabaseConfig struct {
	URL    string        // connection string (preferred)
	DB     *sql.DB       // pre-opened *sql.DB (library borrows, does not close)
	Pool   *pgxpool.Pool // pre-opened pgx pool (library borrows, does not close)
	Driver Driver        // DriverPostgres (default), DriverSQLite, DriverMySQL

	opened bool // internal — true if the library opened the connection
}

// EmailConfig configures SMTP email delivery (transport only).
type EmailConfig struct {
	From string
	Host string
	Port int
	User string
	Pass string
}

// CookieConfig configures the session cookie.
type CookieConfig struct {
	Name     string
	Domain   string
	Path     string
	Secure   bool
	SameSite http.SameSite
}

// SessionConfig groups session lifetime settings.
type SessionConfig struct {
	TTL             time.Duration // absolute hard expiry (default 30d)
	IdleTTL         time.Duration // idle timeout after last activity (default 7d)
	RefreshTokenTTL time.Duration // refresh token absolute expiry (default 30d)
	MaxLifetime     time.Duration // max session lifetime from created_at (0 = no limit)
	GraceWindow     time.Duration // grace period for reusing old refresh token (default 10s)
	TouchDebounce   time.Duration // minimum interval between last_active_at updates (default 5m)
}

// RegistrationConfig controls which registration methods are available.
// Login is ALWAYS unconditional regardless of these flags.
type RegistrationConfig struct {
	EnablePassword            bool          // email+password registration (default true)
	EnableOAuth               bool          // OAuth signup for new users (default true)
	EnableInvite              bool          // invite-code registration (default true)
	AllowPublic               bool          // public registration is allowed (default true)
	RequireEmailVerification  bool          // require email verification on signup (default false)
	InviteTTL                 time.Duration // how long signup invites last (default 7d)
	VerificationCodeTTL       time.Duration // how long verification codes live (default 15m)
}

// OrganizationConfig controls the organizations feature.
type OrganizationConfig struct {
	Enable         bool          // enable orgs feature (default false)
	MaxOrgsPerUser int           // max orgs a user can own (0=default 100, >100 rejected)
	InviteTTL      time.Duration // how long org invites last (default 7d)
}

// AppConfig groups the three identity-level settings for the application instance.
type AppConfig struct {
	Name     string         // app name displayed in emails
	BaseURL  string         // frontend base URL for email links
	Database DatabaseConfig // database connection
}

// SecurityConfig groups security-related settings.
type SecurityConfig struct {
	AllowedOrigins          []string                     // allowed origins for CSRF Origin/Referer check
	AllowMissingCSRFHeaders bool                         // allow requests without Origin/Referer headers (default false)
	CSRFToken               *middleware.CSRFTokenConfig  // double-submit cookie CSRF (optional, disabled by default)
	PasswordPolicy          domain.PasswordPolicy         // password complexity requirements
	TokenTTL                time.Duration                 // how long verification/reset tokens live (default 1h)
}

// ─── Top-level Config ───────────────────────────────────────

// Config is the top-level configuration for go-auth.
// All fields are unexported — use NewConfig + With* functions.
type Config struct {
	appName string
	baseURL string

	database DatabaseConfig

	sessionTTL      time.Duration
	sessionIdleTTL  time.Duration
	refreshTokenTTL time.Duration
	maxLifetime     time.Duration
	graceWindow     time.Duration
	touchDebounce   time.Duration
	tokenTTL        time.Duration

	cookie CookieConfig

	mailer port.Mailer
	email  *EmailConfig

	registration RegistrationConfig

	organizations OrganizationConfig

	allowedOrigins          []string
	allowMissingCSRFHeaders bool
	passwordPolicy          domain.PasswordPolicy
	rateLimit               *ratelimit.Config
	csrfToken               *middleware.CSRFTokenConfig

	providers []port.OAuthProvider

	logger *slog.Logger

	cookieSecureExplicit bool
}

// ─── Validation ──────────────────────────────────────────────

func (c *Config) validate() error {
	var errs []error

	if c.database.Driver == "" {
		errs = append(errs, errors.New("database: driver cannot be empty"))
	}
	if c.database.URL == "" && c.database.DB == nil && c.database.Pool == nil {
		errs = append(errs, errors.New("database: one of URL, DB, or Pool is required"))
	}
	if c.appName == "" {
		errs = append(errs, errors.New("app_name cannot be empty"))
	}

	// Validate BaseURL and auto-derive Cookie.Secure.
	if c.baseURL == "" {
		errs = append(errs, errors.New("base_url is required"))
	} else if parsedURL, err := url.Parse(c.baseURL); err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		errs = append(errs, errors.New("base_url must be a valid HTTP or HTTPS URL"))
	} else if !c.cookieSecureExplicit {
		c.cookie.Secure = parsedURL.Scheme == "https"
	}
	if c.sessionTTL <= 0 {
		errs = append(errs, errors.New("session_ttl must be positive"))
	}
	if c.sessionIdleTTL <= 0 {
		errs = append(errs, errors.New("session_idle_ttl must be positive"))
	}
	if c.sessionIdleTTL > c.sessionTTL {
		errs = append(errs, errors.New("session_idle_ttl must not exceed session_ttl"))
	}
	if c.refreshTokenTTL <= 0 {
		errs = append(errs, errors.New("refresh_token_ttl must be positive"))
	}
	if c.refreshTokenTTL < c.sessionTTL {
		errs = append(errs, errors.New("refresh_token_ttl must not be less than session_ttl"))
	}
	if len(c.allowedOrigins) == 0 {
		errs = append(errs, errors.New("allowed_origins must include at least one origin"))
	}
	for _, o := range c.allowedOrigins {
		if o == "*" {
			errs = append(errs, errors.New("allowed_origins must not contain \"*\" — this disables CSRF protection; list specific origins instead"))
		}
	}
	if c.tokenTTL <= 0 {
		errs = append(errs, errors.New("token_ttl must be positive"))
	}
	if c.cookie.Name == "" {
		errs = append(errs, errors.New("cookie name cannot be empty"))
	}

	// Registration validation
	if (c.registration.RequireEmailVerification || c.registration.EnableInvite) && c.mailer == nil && c.email == nil {
		errs = append(errs, errors.New("email: Mailer or Email config required when RequireEmailVerification or EnableInvite is enabled"))
	}
	if c.registration.RequireEmailVerification && !c.registration.EnablePassword {
		errs = append(errs, errors.New("registration: RequireEmailVerification has no effect when EnablePassword is false"))
	}
	if c.registration.AllowPublic && !c.registration.EnablePassword && !c.registration.EnableOAuth && !c.registration.EnableInvite {
		errs = append(errs, errors.New("registration: AllowPublic is true but no registration method is enabled"))
	}

	if c.organizations.Enable {
		if c.organizations.MaxOrgsPerUser < 0 || c.organizations.MaxOrgsPerUser > 100 {
			errs = append(errs, errors.New("organizations.max_orgs_per_user must be between 0 and 100 (0 = default 100)"))
		}
	}

	seen := map[string]bool{}
	for _, p := range c.providers {
		if p == nil {
			errs = append(errs, errors.New("provider: nil provider registered via WithProvider"))
			continue
		}
		name := p.Name()
		if name == "" {
			errs = append(errs, errors.New("provider: provider with empty name"))
			continue
		}
		if seen[name] {
			errs = append(errs, fmt.Errorf("provider: duplicate provider %q", name))
		}
		seen[name] = true
	}

	return errors.Join(errs...)
}

// ─── Defaults ───────────────────────────────────────────────

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		registration: RegistrationConfig{
			EnablePassword:           true,
			EnableOAuth:              true,
			EnableInvite:             true,
			AllowPublic:              true,
			InviteTTL:                7 * 24 * time.Hour,
			RequireEmailVerification: false,
			VerificationCodeTTL:      15 * time.Minute,
		},
		sessionTTL:      30 * 24 * time.Hour,
		sessionIdleTTL:  7 * 24 * time.Hour,
		refreshTokenTTL: 30 * 24 * time.Hour,
		maxLifetime:     0,
		graceWindow:     10 * time.Second,
		touchDebounce:   5 * time.Minute,
		tokenTTL:        1 * time.Hour,
		rateLimit:       ratelimit.DefaultRateLimitConfig(),
		allowMissingCSRFHeaders: false,
		passwordPolicy: domain.PasswordPolicy{
			MinLength:    8,
			RequireDigit: true,
		},
		cookie: CookieConfig{
			Name:     "goauth_session",
			Path:     "/",
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		},
	}
}

// ─── Constructor ────────────────────────────────────────────

// NewConfig applies the given option functions to DefaultConfig and validates.
// If validation fails, the returned error includes all invalid fields.
func NewConfig(opts ...func(*Config)) (Config, error) {
	cfg := DefaultConfig()
	defaultSecure := cfg.cookie.Secure
	for _, opt := range opts {
		opt(&cfg)
	}
	// If Cookie.Secure differs from the default, the consumer explicitly set it.
	// validate() will not auto-derive from BaseURL in that case.
	if cfg.cookie.Secure != defaultSecure {
		cfg.cookieSecureExplicit = true
	}
	if err := (&cfg).validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ─── With* options ──────────────────────────────────────────

// WithApp configures app-level identity settings.
func WithApp(cfg AppConfig) func(*Config) {
	return func(c *Config) {
		c.appName = cfg.Name
		c.baseURL = cfg.BaseURL
		c.database = cfg.Database
	}
}

// WithCookie sets the session cookie configuration.
func WithCookie(cfg CookieConfig) func(*Config) {
	return func(c *Config) {
		c.cookie = cfg
	}
}

// WithEmail configures SMTP email delivery (transport only).
func WithEmail(cfg EmailConfig) func(*Config) {
	return func(c *Config) {
		c.email = &cfg
	}
}

// WithMailer provides a custom mailer implementation.
func WithMailer(m port.Mailer) func(*Config) {
	return func(c *Config) {
		c.mailer = m
	}
}

// WithSession groups session lifetime settings.
func WithSession(cfg SessionConfig) func(*Config) {
	return func(c *Config) {
		c.sessionTTL = cfg.TTL
		c.sessionIdleTTL = cfg.IdleTTL
		c.refreshTokenTTL = cfg.RefreshTokenTTL
		c.maxLifetime = cfg.MaxLifetime
		c.graceWindow = cfg.GraceWindow
		c.touchDebounce = cfg.TouchDebounce
	}
}

// WithRegistration configures which registration methods are available.
// Login is ALWAYS unconditional regardless of these settings.
func WithRegistration(cfg RegistrationConfig) func(*Config) {
	return func(c *Config) {
		c.registration = cfg
	}
}

// WithOrganizations configures the organizations feature.
func WithOrganizations(cfg OrganizationConfig) func(*Config) {
	return func(c *Config) {
		c.organizations = cfg
	}
}

// WithSecurity groups security-related settings.
func WithSecurity(cfg SecurityConfig) func(*Config) {
	return func(c *Config) {
		c.allowedOrigins = cfg.AllowedOrigins
		c.allowMissingCSRFHeaders = cfg.AllowMissingCSRFHeaders
		c.csrfToken = cfg.CSRFToken
		c.passwordPolicy = cfg.PasswordPolicy
		c.tokenTTL = cfg.TokenTTL
	}
}

// WithRateLimit configures rate limiting.
// Takes a value to force a copy at the call site, preventing shared mutation
// across separate NewConfig calls.
func WithRateLimit(cfg ratelimit.Config) func(*Config) {
	return func(c *Config) {
		c.rateLimit = &cfg
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) func(*Config) {
	return func(c *Config) {
		c.logger = logger
	}
}

// WithProvider registers an OAuth provider.
// The provider's Name() must be non-empty and unique across all registered providers.
// Nil providers are rejected.
func WithProvider(p port.OAuthProvider) func(*Config) {
	return func(c *Config) {
		c.providers = append(c.providers, p)
	}
}
