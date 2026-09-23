package goauth

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// Driver identifies a supported database driver.
type Driver string

// DriverPostgres and the following values identify supported database drivers.
const (
	DriverPostgres Driver = "postgres"
	DriverSQLite   Driver = "sqlite3"
	DriverMySQL    Driver = "mysql"
)

// DatabaseConfig configures the database connection.
// Provide one of URL, DB, or Pool. URL is the preferred option —
// the library will open, validate, and close the connection automatically.
type DatabaseConfig struct {
	URL    string        // connection string (preferred)
	DB     *sql.DB       // pre-opened *sql.DB (library borrows, does not close)
	Pool   *pgxpool.Pool // pre-opened pgx pool (library borrows, does not close)
	Driver Driver        // DriverPostgres, DriverSQLite, DriverMySQL (required: NewConfig rejects an empty driver)

	// Limits apply only to URL-created databases, not borrowed DB or Pool.
	MaxOpenConns    int           // 0 defaults to 25 (PostgreSQL/MySQL), 1 (SQLite)
	MaxIdleConns    *int          // nil defaults to min(2, MaxOpenConns); explicit 0 disables idle retention
	ConnMaxLifetime time.Duration // 0 disables lifetime-based recycling
	ConnMaxIdleTime time.Duration // 0 disables idle-time recycling

	opened bool // internal — owns the SQL handle, including a borrowed-pool adapter
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

// SessionConfig groups session lifetime settings.
type SessionConfig struct {
	TTL             time.Duration // absolute hard expiry (default 30d)
	IdleTTL         time.Duration // idle timeout after last activity (default 7d)
	RefreshTokenTTL time.Duration // refresh token absolute expiry (default 30d)
	MaxLifetime     time.Duration // max session lifetime from created_at (0 = no limit)
	TokenTTL        time.Duration // how long verification/reset tokens live (default 1h)

	// GraceWindow and TouchDebounce are *time.Duration, not time.Duration:
	// nil means "left unset, use the default" (5s / 5m); a non-nil pointer
	// is used exactly as given, including a pointer to 0 to turn the
	// feature off. Set either with goauth.Duration(...) — a plain 0 in a
	// struct literal can't express "off" without also being
	// indistinguishable from "not set," which used to mean an explicit
	// GraceWindow: 0 silently fell back to the 5s default instead of
	// turning the grace window off.
	GraceWindow   *time.Duration // grace period for reusing old refresh token (default 5s)
	TouchDebounce *time.Duration // minimum interval between last_active_at updates (default 5m)
}

// RegistrationConfig controls which registration methods are available.
// Login is ALWAYS unconditional regardless of these flags.
type RegistrationConfig struct {
	EnableEmailPassword        bool          // email+password registration (default true)
	EnableOAuth                bool          // OAuth signup for new users (default true)
	EnableInvite               bool          // invite-code registration (default false; requires a mailer)
	AllowPublic                bool          // public registration is allowed (default true)
	RequireEmailVerification   bool          // require email verification on signup (default false)
	InviteTTL                  time.Duration // how long signup invites last (default 7d)
	VerificationCodeTTL        time.Duration // how long verification codes live (default 15m)
	VerificationResendInterval time.Duration // minimum interval between verification resends (default 60s; negative = no minimum)
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
	FailureMode   audit.FailureMode
	RetentionDays int           // days of audit rows to retain; 0 = keep forever
	QueueSize     int           // Deprecated: the in-memory queue is gone; the outbox is the queue. Ignored.
	Workers       int           // dispatcher workers, default 3
	BatchSize     int           // dispatch batch size, default 50
	FlushInterval time.Duration // dispatch poll interval, default 100ms
	Sinks         []audit.EventSink

	// EnqueueFailureMode resolves the enqueue failure mode per event.
	// Nil = fail-open for every event (the default): a failed durable write
	// never takes authentication down. See audit.Record.
	EnqueueFailureMode audit.EnqueueFailureModeResolver

	// Outbox delivery tuning. Defaults in audit.defaultConfig.
	MaxAttempts   int           // attempts before dead-lettering (default 10)
	ClaimLease    time.Duration // claim lease; must exceed each sink's declared max batch time (default 10m)
	OutboxMaxAge  time.Duration // pending-row age bound (default 7d)
	DeadLetterTTL time.Duration // dead-letter evidence window (default 7d)
	OutboxMaxRows int           // emergency backlog valve (default 100000)
}

// Environment identifies the deployment environment.
type Environment string

// EnvironmentDev and the following values identify deployment environments.
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

// AppConfig groups the identity-level settings for the application instance.
type AppConfig struct {
	Name        string         // app name displayed in emails
	BaseURL     string         // frontend base URL for email links
	Database    DatabaseConfig // database connection
	Environment Environment    // deployment environment (dev, staging, prod)
}

// SecurityConfig groups CSRF, password, and email-link settings. Two-factor
// options moved to TwoFactorConfig — they were six of this struct's thirteen
// fields, and TOTP will add more.
type SecurityConfig struct {
	AllowedOrigins          []string                    // allowed origins for CSRF Origin/Referer check
	AllowMissingCSRFHeaders bool                        // allow requests without Origin/Referer headers (default false)
	CSRFToken               *middleware.CSRFTokenConfig // double-submit cookie CSRF (optional overrides; the layer is on by default)
	PasswordPolicy          domain.PasswordPolicy       // password complexity (zero value = MinLength 8, RequireDigit)

	// DisableCSRFToken turns off the double-submit cookie layer. Origin/Referer
	// checking still applies and cannot be disabled. Intended for deployments
	// with no browser clients — a CLI or a server-to-server API — where CSRF is
	// not part of the threat model and the token round-trip is pure friction.
	//
	// The zero value keeps the layer on: this is spelled as "Disable" rather
	// than "Enable" so that forgetting it is the secure outcome.
	DisableCSRFToken bool

	// AllowHTTPURLs permits http:// links in rendered emails. It governs
	// template rendering, not transport, so it applies to every mailer.
	//
	// Tri-state: nil (the default) derives it — allowed in EnvironmentDev,
	// refused everywhere else. Set it explicitly with AllowPlaintextEmailLinks
	// to allow plaintext links outside a dev environment, or
	// RequireHTTPSEmailLinks to enforce https:// even in development.
	AllowHTTPURLs *bool

	// PepperRotatedAt records when the current WithSecret value went live, as
	// a wall-clock time in UTC. The library HMAC-peppers low-entropy codes
	// (2FA, verification, set-password, delete-account) with a subkey derived
	// from the secret; a code issued before this timestamp was hashed under a
	// previous secret and can never verify, so it is answered expired-style
	// ("resend, don't retry") instead of invalid.
	//
	// Set it — via WithPepperRotatedAt — exactly when you rotate the secret,
	// to the moment the new secret went live, on every instance alike. It is
	// deliberately operator-set rather than derived at boot: every instance
	// behind a load balancer must agree on one value, and a boot-stamped
	// timestamp would make rolling deploys disagree per-request about which
	// codes are stale. Zero (the default, fixed epoch) disables the stale
	// branch: codes are then verified purely by HMAC, and a rotated pepper
	// surfaces as invalid_code rather than expired. Slight future skew is
	// self-correcting — codes read stale only until the timestamp passes.
	PepperRotatedAt time.Time
}

// PasswordPepperConfig configures optional, versioned password peppering.
// CurrentVersion selects the key used for new password writes. Zero disables
// peppering for new writes; Keys may still contain non-zero future versions so
// a rolling deployment can preload them before activation.
//
// Each stored password carries its exact pepper version. Keep every key whose
// version is still present in the database until startup validation reports
// that it is no longer needed.
type PasswordPepperConfig struct {
	CurrentVersion uint32
	Keys           map[uint32]string
}

// TwoFactorConfig groups the email two-factor settings, split out of
// SecurityConfig where they were six of thirteen fields.
type TwoFactorConfig struct {
	// RequireEmail2FA makes email two-factor mandatory for every password
	// login. Enable/Disable both reject while it is on, so users cannot opt
	// out. OAuth logins are not covered — see docs/security.mdx.
	RequireEmail2FA bool

	// DefaultEnabled seeds User.TwoFactorEnabled at registration. Users can
	// still opt out with Disable; use RequireEmail2FA for the mandatory case.
	DefaultEnabled bool

	// CodeTTL is how long a 2FA login code lives (default 5m). Deliberately
	// shorter than VerificationCodeTTL: a 6-digit code has ~20 fewer bits than
	// the 8-char alphanumeric codes used elsewhere.
	CodeTTL time.Duration

	// DisableChallengeBinding turns off the challenge binding cookie, which
	// otherwise ties a 2FA challenge to the browser that started it.
	//
	// As with DisableCSRFToken, the zero value keeps the protection on: this is
	// spelled as "Disable" so that forgetting it is the secure outcome. Intended
	// for the same consumers — a CLI or server-to-server API with no browser —
	// where a mandatory cookie makes 2FA unusable. With it set, the challenge id
	// alone identifies the challenge, so treat it as a secret and keep it out of
	// logs.
	DisableChallengeBinding bool

	// ChallengeCookieName overrides the binding cookie name
	// (default "_2fa_challenge").
	ChallengeCookieName string

	// DisableAdminTwoFactor turns off the unconditional email two-factor
	// challenge on POST /auth/admin/login. Intended for API-only deployments
	// with no email delivery at all — every other email-gated feature
	// (RequireEmailVerification, EnableInvite, RequireEmail2FA, DefaultEnabled)
	// must also be off before a mailer becomes optional; see NewConfig's
	// validation error if one still needs it.
	//
	// The zero value keeps AdminLogin's 2FA on: this is spelled as "Disable"
	// so that forgetting it is the secure outcome.
	DisableAdminTwoFactor bool
}
