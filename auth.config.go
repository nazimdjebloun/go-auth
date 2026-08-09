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

// Disabled turns off a duration-based feature whose zero value means "unset,
// use the default" — SessionConfig.GraceWindow and SessionConfig.TouchDebounce.
// Without it those two could only ever be defaulted, never switched off.
const Disabled time.Duration = -1

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
	From    string
	Host    string
	Port    int
	User    string
	Pass    string
	TLSMode TLSMode
}

// CookieConfig configures the session and refresh cookies. Zero-valued fields
// keep their defaults — see applyDefaults.
type CookieConfig struct {
	Name        string // session cookie name (default "goauth_session")
	RefreshName string // refresh cookie name (default "goauth_refresh")
	Domain      string
	Path        string // default "/"
	SameSite    http.SameSite

	// Secure is tri-state. nil (the default) derives it from BaseURL and
	// Environment: true unless the app is on http:// in a dev environment.
	// Set it explicitly with SecureAlways/SecureNever to override that.
	Secure *bool
}

// Bool returns a pointer to v, for the tri-state config fields where nil means
// "derive from the environment": CookieConfig.Secure and
// SecurityConfig.AllowHTTPURLs.
func Bool(v bool) *bool { return &v }

// SecureAlways and SecureNever are readable spellings of Bool for
// CookieConfig.Secure. SecureNever is for local development over http:// only
// — browsers will send the cookie over plaintext connections.
func SecureAlways() *bool { return Bool(true) }
func SecureNever() *bool  { return Bool(false) }

// SessionConfig groups session lifetime settings.
type SessionConfig struct {
	TTL             time.Duration // absolute hard expiry (default 30d)
	IdleTTL         time.Duration // idle timeout after last activity (default 7d)
	RefreshTokenTTL time.Duration // refresh token absolute expiry (default 30d)
	MaxLifetime     time.Duration // max session lifetime from created_at (0 = no limit)
	GraceWindow     time.Duration // grace period for reusing old refresh token (default 5s, Disabled = off)
	TouchDebounce   time.Duration // minimum interval between last_active_at updates (default 5m, Disabled = off)
}

// RegistrationConfig controls which registration methods are available.
// Login is ALWAYS unconditional regardless of these flags.
type RegistrationConfig struct {
	EnableEmailPassword      bool          // email+password registration (default true)
	EnableOAuth              bool          // OAuth signup for new users (default true)
	EnableInvite             bool          // invite-code registration (default false; requires a mailer)
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
	PasswordPolicy          domain.PasswordPolicy       // password complexity (zero value = MinLength 8, RequireDigit)
	TokenTTL                time.Duration               // how long verification/reset tokens live (default 1h)

	// AllowHTTPURLs permits http:// links in rendered emails. It governs
	// template rendering, not transport, so it applies to every mailer.
	//
	// Tri-state: nil (the default) derives it — allowed in EnvironmentDev,
	// refused everywhere else. Set it with Bool(true) to allow plaintext links
	// outside a dev environment, or Bool(false) to enforce https:// even in
	// development.
	AllowHTTPURLs *bool
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
	allowHTTPURLsOpt           *bool // consumer intent; nil = derive
	allowHTTPURLs              bool  // resolved by applyDefaults — read this
	rateLimit                  *ratelimit.Config
	csrfToken                  *middleware.CSRFTokenConfig

	providers []port.OAuthProvider

	audit      AuditConfig
	auditSinks []audit.EventSink

	logger *slog.Logger

	// cookieSecure is the resolved value of cookie.Secure, filled by
	// applyDefaults. Read this, never cookie.Secure, which is user intent.
	cookieSecure bool

	// registrationSet records whether WithRegistration was called. Bool fields
	// have no "unset" state, so section-level defaults can only be applied to a
	// section the consumer never touched — see applyDefaults.
	registrationSet bool

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

	if c.baseURL == "" {
		errs = append(errs, errors.New("base_url is required"))
	} else if parsedURL, err := url.Parse(c.baseURL); err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		errs = append(errs, errors.New("base_url must be a valid HTTP or HTTPS URL"))
	}
	switch c.environment.normalize() {
	case EnvironmentDev, EnvironmentStaging, EnvironmentProd:
	default:
		errs = append(errs, fmt.Errorf("environment must be one of dev, staging, or prod, got %q", c.environment))
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
	// applyDefaults turns the Disabled sentinel into 0, so anything still
	// negative here is a bad value rather than a deliberate opt-out.
	if c.graceWindow < 0 {
		errs = append(errs, errors.New("session grace_window must not be negative (use goauth.Disabled to turn it off)"))
	}
	if c.touchDebounce < 0 {
		errs = append(errs, errors.New("session touch_debounce must not be negative (use goauth.Disabled to turn it off)"))
	}
	if c.maxLifetime < 0 {
		errs = append(errs, errors.New("session max_lifetime must not be negative (0 = no limit)"))
	} else if c.maxLifetime > 0 && c.maxLifetime < c.sessionTTL {
		errs = append(errs, errors.New("session max_lifetime must not be less than session_ttl"))
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
	if c.registration.InviteTTL <= 0 {
		errs = append(errs, errors.New("registration: invite_ttl must be positive"))
	}
	if c.registration.VerificationCodeTTL <= 0 {
		errs = append(errs, errors.New("registration: verification_code_ttl must be positive"))
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
		if c.organizations.InviteTTL <= 0 {
			errs = append(errs, errors.New("organizations.invite_ttl must be positive"))
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

// defaultRegistration is applied only when WithRegistration was never called.
// Invites are off by default: turning them on requires a mailer (see
// validate), so defaulting them on would make the zero configuration invalid.
func defaultRegistration() RegistrationConfig {
	return RegistrationConfig{
		EnableEmailPassword:      true,
		EnableOAuth:              true,
		EnableInvite:             false,
		AllowPublic:              true,
		RequireEmailVerification: false,
		InviteTTL:                7 * 24 * time.Hour,
		VerificationCodeTTL:      15 * time.Minute,
	}
}

// applyDefaults fills every field the consumer left unset. It runs in
// NewConfig after all options have been applied, which is the only point at
// which "unset" is knowable: an option that assigns a struct wholesale cannot
// tell a zero field from an omitted one, so seeding defaults *before* options
// run means any partially-filled struct silently destroys them.
//
// The rule is: zero means unset. Fields where zero is a meaningful value are
// listed here explicitly and left alone — MaxLifetime (0 = no limit),
// MaxOrgsPerUser (0 = default 100), VerificationResendInterval (0 = no
// minimum), and every bool, which is why sections whose defaults include a
// true bool are tracked with a *Set flag instead.
func (c *config) applyDefaults() {
	if c.environment == "" {
		c.environment = EnvironmentProd
	}

	if !c.registrationSet {
		c.registration = defaultRegistration()
	}
	if c.registration.InviteTTL == 0 {
		c.registration.InviteTTL = 7 * 24 * time.Hour
	}
	if c.registration.VerificationCodeTTL == 0 {
		c.registration.VerificationCodeTTL = 15 * time.Minute
	}
	if c.organizations.InviteTTL == 0 {
		c.organizations.InviteTTL = 7 * 24 * time.Hour
	}

	if c.sessionTTL == 0 {
		c.sessionTTL = 30 * 24 * time.Hour
	}
	if c.sessionIdleTTL == 0 {
		c.sessionIdleTTL = 7 * 24 * time.Hour
	}
	if c.refreshTokenTTL == 0 {
		c.refreshTokenTTL = 30 * 24 * time.Hour
	}
	// Only the exact Disabled sentinel normalizes to off. Any other negative
	// is left as-is for validate() to reject, so a typo like -5*time.Second
	// is an error rather than a silent "off".
	switch c.graceWindow {
	case 0:
		c.graceWindow = 5 * time.Second
	case Disabled:
		c.graceWindow = 0
	}
	switch c.touchDebounce {
	case 0:
		c.touchDebounce = 5 * time.Minute
	case Disabled:
		c.touchDebounce = 0
	}
	if c.tokenTTL == 0 {
		c.tokenTTL = 1 * time.Hour
	}

	if c.passwordPolicy == (domain.PasswordPolicy{}) {
		c.passwordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true}
	}

	if c.cookie.Name == "" {
		c.cookie.Name = "goauth_session"
	}
	if c.cookie.RefreshName == "" {
		c.cookie.RefreshName = "goauth_refresh"
	}
	if c.cookie.Path == "" {
		c.cookie.Path = "/"
	}
	if c.cookie.SameSite == 0 {
		c.cookie.SameSite = http.SameSiteLaxMode
	}
	c.cookieSecure = c.resolveCookieSecure()

	if c.rateLimit == nil {
		c.rateLimit = ratelimit.DefaultRateLimitConfig()
	}

	c.allowHTTPURLs = c.resolveAllowHTTPURLs()
}

// resolveAllowHTTPURLs honours an explicit SecurityConfig.AllowHTTPURLs and
// otherwise derives it: http:// links are acceptable in a dev environment and
// refused everywhere else.
func (c *config) resolveAllowHTTPURLs() bool {
	if c.allowHTTPURLsOpt != nil {
		return *c.allowHTTPURLsOpt
	}
	return c.environment.normalize() == EnvironmentDev
}

// resolveCookieSecure honours an explicit CookieConfig.Secure and otherwise
// derives it: secure unless the app is served over http:// in development.
func (c *config) resolveCookieSecure() bool {
	if c.cookie.Secure != nil {
		return *c.cookie.Secure
	}
	if c.environment.normalize() != EnvironmentDev {
		return true
	}
	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return true
	}
	return parsed.Scheme != "http"
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
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	cfg.applyDefaults()
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
		c.verificationResendInterval = cfg.VerificationResendInterval
	}
}

// WithCookie sets the cookie configuration. Fields left at their zero value
// keep their defaults — see applyDefaults.
func WithCookie(cfg CookieConfig) Option {
	return func(c *config) {
		c.cookie = cfg
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
//
// Calling this replaces the default registration settings wholesale rather
// than merging into them — the bool fields have no "unset" state, so an
// omitted flag is indistinguishable from a deliberate false. Enable every
// method you want; only the TTLs fall back to defaults when left at zero.
func WithRegistration(cfg RegistrationConfig) Option {
	return func(c *config) {
		c.registration = cfg
		c.registrationSet = true
	}
}

// WithOrganizations configures the organizations feature.
func WithOrganizations(cfg OrganizationConfig) Option {
	return func(c *config) {
		c.organizations = cfg
	}
}

// WithSecurity groups security-related settings. A zero-valued PasswordPolicy
// or TokenTTL keeps its default — see applyDefaults.
func WithSecurity(cfg SecurityConfig) Option {
	return func(c *config) {
		c.allowedOrigins = append([]string(nil), cfg.AllowedOrigins...)
		c.allowMissingCSRFHeaders = cfg.AllowMissingCSRFHeaders
		if cfg.CSRFToken != nil {
			tok := *cfg.CSRFToken // copy: do not alias the consumer's struct
			c.csrfToken = &tok
		}
		c.passwordPolicy = cfg.PasswordPolicy
		c.tokenTTL = cfg.TokenTTL
		c.allowHTTPURLsOpt = cfg.AllowHTTPURLs
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

// WithRateLimit configures rate limiting. The Routes map and TrustedIPs slice
// are deep-copied: a value parameter alone only copies the map header, so
// later WithRateLimitRoute calls would otherwise write through to the
// consumer's own map and leak across separate NewConfig calls.
func WithRateLimit(cfg ratelimit.Config) Option {
	return func(c *config) {
		clone := cfg
		if cfg.Routes != nil {
			clone.Routes = make(map[string]ratelimit.Rate, len(cfg.Routes))
			for k, v := range cfg.Routes {
				clone.Routes[k] = v
			}
		}
		clone.TrustedIPs = append([]string(nil), cfg.TrustedIPs...)
		clone.DisabledPaths = append([]string(nil), cfg.DisabledPaths...)
		// Store and Logger are deliberately shared: they are live objects the
		// consumer owns, not data to be snapshotted.
		c.rateLimit = &clone
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
		c.rateLimit.TrustedIPs = append([]string(nil), ips...)
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

// WithAudit configures audit logging. Sinks listed in cfg are registered once
// regardless of how many times this option is applied; appending them here
// instead would duplicate every sink — and so every audit event — on a repeat
// call. New() reads cfg.Sinks and the WithAuditSink list together.
func WithAudit(cfg AuditConfig) Option {
	return func(c *config) {
		c.audit = cfg
	}
}

// WithAuditSink adds a custom audit event sink (e.g. Kafka, NATS, webhook).
// Only takes effect when audit is enabled via WithAudit.
func WithAuditSink(sink audit.EventSink) Option {
	return func(c *config) {
		c.auditSinks = append(c.auditSinks, sink)
	}
}
