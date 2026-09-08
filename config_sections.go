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

type Driver string

const (
	DriverPostgres Driver = "postgres"
	DriverSQLite   Driver = "sqlite3"
	DriverMySQL    Driver = "mysql"
)

const bcryptCost = 12
const tokenLength = 32

// Duration returns a pointer to d, for SessionConfig.GraceWindow and
// SessionConfig.TouchDebounce — Go can't take the address of a duration
// literal directly. Both fields are *time.Duration rather than
// time.Duration specifically so 0 can mean "explicitly off" without
// colliding with "left unset, use the default": leave the field nil for
// the default, or set it with goauth.Duration(0) to turn the feature off,
// goauth.Duration(10*time.Second) for a custom value, and so on.
func Duration(d time.Duration) *time.Duration { return &d }

// ─── Config sub-types ───────────────────────────────────────

type TLSMode int

const (
	TLSStart    TLSMode = iota // STARTTLS, typically port 587 — the zero value, so an unset TLSMode is never plaintext
	TLSImplicit                // implicit TLS, typically port 465
	TLSNone                    // plaintext — dev/local only
)

// DatabaseConfig configures the database connection.
// Provide one of URL, DB, or Pool. URL is the preferred option —
// the library will open, validate, and close the connection automatically.
type DatabaseConfig struct {
	URL    string        // connection string (preferred)
	DB     *sql.DB       // pre-opened *sql.DB (library borrows, does not close)
	Pool   *pgxpool.Pool // pre-opened pgx pool (library borrows, does not close)
	Driver Driver        // DriverPostgres (default), DriverSQLite, DriverMySQL

	opened     bool // internal — true if the library opened DB itself
	poolOpened bool // internal — true if the library opened Pool itself
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

// boolPtr returns a pointer to v — the shared implementation behind the
// readable spellings below, for the tri-state config fields where nil means
// "derive from the environment": CookieConfig.Secure and
// SecurityConfig.AllowHTTPURLs.
func boolPtr(v bool) *bool { return &v }

// SecureAlways and SecureNever are readable spellings for CookieConfig.Secure.
// SecureNever is for local development over http:// only — browsers will send
// the cookie over plaintext connections.
func SecureAlways() *bool { return boolPtr(true) }
func SecureNever() *bool  { return boolPtr(false) }

// AllowPlaintextEmailLinks and RequireHTTPSEmailLinks are readable spellings
// for SecurityConfig.AllowHTTPURLs. AllowPlaintextEmailLinks permits http://
// links in emails outside a dev environment; RequireHTTPSEmailLinks enforces
// https:// even inside one.
func AllowPlaintextEmailLinks() *bool { return boolPtr(true) }
func RequireHTTPSEmailLinks() *bool   { return boolPtr(false) }

// SessionConfig groups session lifetime settings.
type SessionConfig struct {
	TTL             time.Duration // absolute hard expiry (default 30d)
	IdleTTL         time.Duration // idle timeout after last activity (default 7d)
	RefreshTokenTTL time.Duration // refresh token absolute expiry (default 30d)
	MaxLifetime     time.Duration // max session lifetime from created_at (0 = no limit)

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
	CSRFToken               *middleware.CSRFTokenConfig // double-submit cookie CSRF (optional overrides; the layer is on by default)
	PasswordPolicy          domain.PasswordPolicy       // password complexity (zero value = MinLength 8, RequireDigit)
	TokenTTL                time.Duration               // how long verification/reset tokens live (default 1h)

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

	// RequireEmail2FA makes email two-factor mandatory for every password
	// login. Enable/Disable both reject while it is on, so users cannot opt
	// out. OAuth logins are not covered — see docs/security.mdx.
	RequireEmail2FA bool

	// DefaultTwoFactorEnabled seeds User.TwoFactorEnabled at registration.
	// Users can still opt out with Disable; use RequireEmail2FA for the
	// mandatory case.
	DefaultTwoFactorEnabled bool

	// TwoFactorCodeTTL is how long a 2FA login code lives (default 5m).
	// Deliberately shorter than VerificationCodeTTL: a 6-digit code has ~20
	// fewer bits than the 8-char alphanumeric codes used elsewhere.
	TwoFactorCodeTTL time.Duration

	// DisableTwoFactorChallengeBinding turns off the challenge binding cookie,
	// which otherwise ties a 2FA challenge to the browser that started it.
	//
	// As with DisableCSRFToken, the zero value keeps the protection on: this is
	// spelled as "Disable" so that forgetting it is the secure outcome. Intended
	// for the same consumers — a CLI or server-to-server API with no browser —
	// where a mandatory cookie makes 2FA unusable. With it set, the challenge id
	// alone identifies the challenge, so treat it as a secret and keep it out of
	// logs.
	DisableTwoFactorChallengeBinding bool

	// TwoFactorChallengeCookieName overrides the binding cookie name
	// (default "_2fa_challenge").
	TwoFactorChallengeCookieName string

	// DisableAdminTwoFactor turns off the unconditional email two-factor
	// challenge on POST /auth/admin/login. Intended for API-only deployments
	// with no email delivery at all — every other email-gated feature
	// (RequireEmailVerification, EnableInvite, RequireEmail2FA,
	// DefaultTwoFactorEnabled) must also be off before a mailer becomes
	// optional; see NewConfig's validation error if one still needs it.
	//
	// The zero value keeps AdminLogin's 2FA on: this is spelled as "Disable"
	// so that forgetting it is the secure outcome.
	DisableAdminTwoFactor bool
}
