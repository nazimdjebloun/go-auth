package goauth

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/audit"
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

type TLSMode int

const (
	TLSNone     TLSMode = iota // plaintext — dev/local only
	TLSStart                   // STARTTLS, typically port 587
	TLSImplicit                // implicit TLS, typically port 465
)

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
	From          string
	Host          string
	Port          int
	User          string
	Pass          string
	TLSMode       TLSMode
	AllowHTTPURLs bool // allow http:// URLs in email templates (dev only, default false)
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
	EnableEmailPassword      bool          // email+password registration (default true)
	EnableOAuth              bool          // OAuth signup for new users (default true)
	EnableInvite             bool          // invite-code registration (default true)
	AllowPublic              bool          // public registration is allowed (default true)
	RequireEmailVerification bool          // require email verification on signup (default false)
	InviteTTL                time.Duration // how long signup invites last (default 7d)
	VerificationCodeTTL      time.Duration // how long verification codes live (default 15m)
}

// OrganizationConfig controls the organizations feature.
type OrganizationConfig struct {
	Enable         bool          // enable orgs feature (default false)
	MaxOrgsPerUser int           // max orgs a user can own (0=default 100, >100 rejected)
	InviteTTL      time.Duration // how long org invites last (default 7d)
}

// AuditConfig controls audit logging behavior.
type AuditConfig struct {
	Enabled       bool
	FailureMode   audit.AuditFailureMode
	RetentionDays int           // default 90, 0 = forever
	QueueSize     int           // default 1000
	Workers       int           // default 3
	BatchSize     int           // default 50
	FlushInterval time.Duration // default 100ms
	Sinks         []audit.EventSink
}

type Environment string

const (
	EnvironmentDev     Environment = "dev"
	EnvironmentStaging Environment = "staging"
	EnvironmentProd    Environment = "prod"
)

func (e Environment) normalize() Environment {
	switch string(e) {
	case "development":
		return EnvironmentDev
	case "production":
		return EnvironmentProd
	default:
		return e
	}
}

// AppConfig groups the three identity-level settings for the application instance.
type AppConfig struct {
	Name                       string         // app name displayed in emails
	BaseURL                    string         // frontend base URL for email links
	Database                   DatabaseConfig // database connection
	Environment                Environment    // deployment environment (dev, staging, prod)
	VerificationResendInterval time.Duration  // minimum interval between verification resends (0 = no minimum)
}

// SecurityConfig groups security-related settings.
type SecurityConfig struct {
	AllowedOrigins          []string                    // allowed origins for CSRF Origin/Referer check
	AllowMissingCSRFHeaders bool                        // allow requests without Origin/Referer headers (default false)
	CSRFToken               *middleware.CSRFTokenConfig // double-submit cookie CSRF (optional, disabled by default)
	PasswordPolicy          domain.PasswordPolicy       // password complexity requirements
	TokenTTL                time.Duration               // how long verification/reset tokens live (default 1h)
}

// ─── Top-level config ───────────────────────────────────────

// config is the top-level configuration for go-auth. The type itself is
// unexported (not just its fields), so NewConfig(opts...) is the only way
// to produce one — it cannot be named, zero-valued, or hand-built from
// outside this package, which makes NewConfig the single supported way to
// configure go-auth rather than merely the recommended one.
type config struct {
	appName     string
	baseURL     string
	environment Environment

	database DatabaseConfig

	sessionTTL      time.Duration
	sessionIdleTTL  time.Duration
	refreshTokenTTL time.Duration
	maxLifetime     time.Duration
	graceWindow     time.Duration
	touchDebounce   time.Duration
	tokenTTL        time.Duration

	cookie CookieConfig

	mailer           port.Mailer
	email            *EmailConfig
	templateProvider port.TemplateProvider

	registration RegistrationConfig

	organizations OrganizationConfig

	allowedOrigins             []string
	allowMissingCSRFHeaders    bool
	secret                     string // app-wide HMAC signing key; signers MUST fail closed on empty (see csrf_token.go) - validate() only guards NewConfig
	passwordPolicy             domain.PasswordPolicy
	verificationResendInterval time.Duration
	rateLimit                  *ratelimit.Config
	csrfToken                  *middleware.CSRFTokenConfig

	providers []port.OAuthProvider

	audit      AuditConfig
	auditSinks []audit.EventSink

	logger *slog.Logger

	cookieSecureExplicit bool

	// validated is set only by NewConfig() after validate() succeeds. New()
	// checks it too — belt-and-suspenders alongside config being unexported,
	// in case that ever changes.
	validated bool
}

// ─── Validation ──────────────────────────────────────────────

func (c *config) validate() error {
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
		env := c.environment.normalize()
		c.cookie.Secure = parsedURL.Scheme == "https" || env != EnvironmentDev
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
	if len(c.secret) == 0 {
		errs = append(errs, errors.New("secret: signing secret is required"))
	} else if len(c.secret) < 32 {
		errs = append(errs, errors.New("secret: signing secret must be at least 32 bytes for HMAC-SHA256"))
	}

	// Email validation — only check SMTP fields when no custom mailer is set
	if c.email != nil && c.mailer == nil {
		e := c.email
		if e.Host == "" {
			errs = append(errs, errors.New("email: host is required"))
		}
		if e.Port <= 0 || e.Port > 65535 {
			errs = append(errs, fmt.Errorf("email: port must be between 1 and 65535, got %d", e.Port))
		}
		if e.From == "" {
			errs = append(errs, errors.New("email: from address is required"))
		} else if _, err := mail.ParseAddress(e.From); err != nil {
			errs = append(errs, fmt.Errorf("email: from address %q is not valid: %w", e.From, err))
		}
		if (e.User == "") != (e.Pass == "") {
			errs = append(errs, errors.New("email: user and pass must both be set or both be empty"))
		}
		if e.TLSMode < TLSNone || e.TLSMode > TLSImplicit {
			errs = append(
				errs,
				fmt.Errorf("email: tls mode must be one of TLSNone, TLSStart, or TLSImplicit, got %d", e.TLSMode),
			)
		}
	}
	if (c.registration.RequireEmailVerification || c.registration.EnableInvite) && c.mailer == nil && c.email == nil {
		errs = append(errs, errors.New("email: Mailer or Email config required when RequireEmailVerification or EnableInvite is enabled"))
	}
	if c.registration.RequireEmailVerification && !c.registration.EnableEmailPassword && !c.registration.EnableOAuth {
		errs = append(errs, errors.New("registration: RequireEmailVerification has no effect when both EnableEmailPassword and EnableOAuth are disabled"))
	}
	if c.registration.AllowPublic && !c.registration.EnableEmailPassword && !c.registration.EnableOAuth && !c.registration.EnableInvite {
		errs = append(errs, errors.New("registration: AllowPublic is true but no registration method is enabled"))
	}

	if c.organizations.Enable {
		if c.organizations.MaxOrgsPerUser < 0 || c.organizations.MaxOrgsPerUser > 100 {
			errs = append(errs, errors.New("organizations.max_orgs_per_user must be between 0 and 100 (0 = default 100)"))
		}
	}

	if c.rateLimit != nil && c.rateLimit.Enabled {
		rl := c.rateLimit
		if rl.Store == nil {
			errs = append(errs, errors.New("rate_limit: store is nil but enabled is true - provide ratelimit.NewMemoryStore() or a distributed store"))
		}
		if err := validateRate("default", rl.Default); err != nil {
			errs = append(errs, err)
		}
		for route, rate := range rl.Routes {
			if err := validateRate(route, rate); err != nil {
				errs = append(errs, err)
			}
		}
		if rl.IPv6Subnet < 1 || rl.IPv6Subnet > 128 {
			errs = append(errs, fmt.Errorf("rate_limit: ipv6_subnet must be between 1 and 128, got %d", rl.IPv6Subnet))
		}
		for _, ip := range rl.TrustedIPs {
			if net.ParseIP(ip) == nil {
				if _, _, err := net.ParseCIDR(ip); err != nil {
					errs = append(errs, fmt.Errorf("rate_limit: trusted_ips contains invalid IP/CIDR %q", ip))
				}
			}
		}
		if rl.IPAddressHeader != "" && len(rl.TrustedIPs) == 0 {
			errs = append(errs, errors.New("rate_limit: ip_address_header is set but trusted_ips is empty - client-supplied header can be spoofed to bypass rate limiting"))
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

func validateRate(name string, r ratelimit.Rate) error {
	if r.Requests <= 0 {
		return fmt.Errorf("rate_limit: route %q requests must be positive, got %d", name, r.Requests)
	}
	if r.Window <= 0 {
		return fmt.Errorf("rate_limit: route %q window must be positive, got %s", name, r.Window)
	}
	return nil
}

// ─── Defaults ───────────────────────────────────────────────

// defaultConfig returns a config with sensible defaults. Unexported: it's
// an internal building block for NewConfig, not a second public entry point.
func defaultConfig() config {
	return config{
		environment: EnvironmentProd,
		registration: RegistrationConfig{
			EnableEmailPassword:      true,
			EnableOAuth:              true,
			EnableInvite:             true,
			AllowPublic:              true,
			InviteTTL:                7 * 24 * time.Hour,
			RequireEmailVerification: false,
			VerificationCodeTTL:      15 * time.Minute,
		},
		sessionTTL:              30 * 24 * time.Hour,
		sessionIdleTTL:          7 * 24 * time.Hour,
		refreshTokenTTL:         30 * 24 * time.Hour,
		maxLifetime:             0,
		graceWindow:             5 * time.Second,
		touchDebounce:           5 * time.Minute,
		tokenTTL:                1 * time.Hour,
		rateLimit:               ratelimit.DefaultRateLimitConfig(),
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

// Option configures a config. It is an alias rather than a defined type so
// that the With* functions keep returning the same underlying signature, and
// consumers can name it — `[]goauth.Option{...}` — to build option sets
// conditionally. Naming the option type does not weaken the guarantee above:
// config itself stays unexported, so NewConfig remains the only way to
// produce a value New() accepts.
type Option = func(*config)

// NewConfig applies the given option functions to a default config and
// validates the result. If validation fails, the returned error includes
// all invalid fields. This is the only way to produce a config that New()
// will accept — see the config type's doc comment.
func NewConfig(opts ...Option) (config, error) {
	cfg := defaultConfig()
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
		return config{}, err
	}
	cfg.validated = true
	return cfg, nil
}

// ─── With* options ──────────────────────────────────────────

// WithApp configures app-level identity settings.
func WithApp(cfg AppConfig) Option {
	return func(c *config) {
		c.appName = cfg.Name
		c.baseURL = cfg.BaseURL
		c.database = cfg.Database
		c.environment = cfg.Environment
		if cfg.VerificationResendInterval > 0 {
			c.verificationResendInterval = cfg.VerificationResendInterval
		}
	}
}

// WithCookie sets the session cookie configuration. Fields left at their zero
// value keep their defaults: an empty Name keeps "goauth_session", an empty
// Path keeps "/", and an unset SameSite keeps SameSiteLaxMode.
func WithCookie(cfg CookieConfig) Option {
	return func(c *config) {
		if cfg.Name != "" {
			c.cookie.Name = cfg.Name
		}
		c.cookie.Domain = cfg.Domain
		if cfg.Path != "" {
			c.cookie.Path = cfg.Path
		}
		c.cookie.Secure = cfg.Secure
		if cfg.SameSite != 0 {
			c.cookie.SameSite = cfg.SameSite
		}
	}
}

// WithEmail configures SMTP email delivery (transport only).
func WithEmail(cfg EmailConfig) Option {
	return func(c *config) {
		c.email = &cfg
	}
}

// WithMailer provides a custom mailer implementation.
func WithMailer(m port.Mailer) Option {
	return func(c *config) {
		c.mailer = m
	}
}

// WithTemplates provides a custom email template provider.
// When set, the provider's Render method is called for every email instead of
// the built-in default templates.
func WithTemplates(p port.TemplateProvider) Option {
	return func(c *config) {
		c.templateProvider = p
	}
}

// WithSession groups session lifetime settings.
func WithSession(cfg SessionConfig) Option {
	return func(c *config) {
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
func WithRegistration(cfg RegistrationConfig) Option {
	return func(c *config) {
		c.registration = cfg
	}
}

// WithOrganizations configures the organizations feature.
func WithOrganizations(cfg OrganizationConfig) Option {
	return func(c *config) {
		c.organizations = cfg
	}
}

// WithSecurity groups security-related settings.
func WithSecurity(cfg SecurityConfig) Option {
	return func(c *config) {
		c.allowedOrigins = cfg.AllowedOrigins
		c.allowMissingCSRFHeaders = cfg.AllowMissingCSRFHeaders
		c.csrfToken = cfg.CSRFToken
		c.passwordPolicy = cfg.PasswordPolicy
		c.tokenTTL = cfg.TokenTTL
	}
}

// WithSecret sets the app-wide signing secret. This is the first signing key
// material the library introduces and is intentionally general-purpose: it is
// used to sign CSRF tokens today and any future HMAC-based tokens this library
// adds. It is required and must be at least 32 bytes for HMAC-SHA256. Do not
// commit secrets to source control; supply it from the environment.
func WithSecret(secret string) Option {
	return func(c *config) {
		c.secret = secret
	}
}

// WithRateLimit configures rate limiting.
// Takes a value to force a copy at the call site, preventing shared mutation
// across separate NewConfig calls.
func WithRateLimit(cfg ratelimit.Config) Option {
	return func(c *config) {
		c.rateLimit = &cfg
	}
}

// WithRateLimitEnabled toggles rate limiting on/off without touching Routes, Default, or Store.
func WithRateLimitEnabled(enabled bool) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.Enabled = enabled
	}
}

// WithRateLimitDefault overrides only the fallback rate applied to routes not present in Routes.
func WithRateLimitDefault(r ratelimit.Rate) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.Default = r
	}
}

// WithRateLimitRoute overrides or adds a single route's rate without replacing the rest of the Routes table.
func WithRateLimitRoute(pattern string, r ratelimit.Rate) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		if c.rateLimit.Routes == nil {
			c.rateLimit.Routes = map[string]ratelimit.Rate{}
		}
		c.rateLimit.Routes[pattern] = r
	}
}

// WithRateLimitStore swaps the backing store (e.g. a Redis-backed Store) without touching Routes or Default.
func WithRateLimitStore(s ratelimit.Store) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.Store = s
	}
}

// WithTrustedIPs sets the list of IPs/CIDRs trusted to supply IPAddressHeader.
func WithTrustedIPs(ips []string) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.TrustedIPs = ips
	}
}

// WithIPv6Subnet sets the subnet prefix length used to bucket IPv6 clients for rate limiting.
func WithIPv6Subnet(prefixLen int) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.IPv6Subnet = prefixLen
	}
}

// WithIPAddressHeader sets which header to trust for client IP (e.g. "CF-Connecting-IP").
// Requires TrustedIPs to be set - validated in config.validate().
func WithIPAddressHeader(header string) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.IPAddressHeader = header
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		c.logger = logger
	}
}

// WithProvider registers an OAuth provider.
// The provider's Name() must be non-empty and unique across all registered providers.
// Nil providers are rejected.
func WithProvider(p port.OAuthProvider) Option {
	return func(c *config) {
		c.providers = append(c.providers, p)
	}
}

// WithAudit configures audit logging.
func WithAudit(cfg AuditConfig) Option {
	return func(c *config) {
		c.audit = cfg
		c.auditSinks = append(c.auditSinks, cfg.Sinks...)
	}
}

// WithAuditSink adds a custom audit event sink (e.g. Kafka, NATS, webhook).
// Only takes effect when audit is enabled via WithAudit.
func WithAuditSink(sink audit.EventSink) Option {
	return func(c *config) {
		c.auditSinks = append(c.auditSinks, sink)
	}
}
