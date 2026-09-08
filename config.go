package goauth

import (
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// Config is the top-level configuration for go-auth. Build it with
// NewConfig(opts...), which is the only way to produce one New() accepts.
//
// Every field is unexported, and that — not the name of the type — is what
// makes NewConfig the single supported entry point: &goauth.Config{}
// compiles but has no field a caller outside this package can set, and New()
// rejects it. The type is exported so it can be named — held in a variable,
// stored on a struct, returned from a helper that assembles options from the
// environment — none of which was possible while the type was unexported.
type Config struct {
	appName     string
	baseURL     string
	environment Environment

	database DatabaseConfig

	sessionTTL      time.Duration
	sessionIdleTTL  time.Duration
	refreshTokenTTL time.Duration
	maxLifetime     time.Duration

	graceWindowOpt   *time.Duration // consumer intent; nil = derive
	touchDebounceOpt *time.Duration
	graceWindow      time.Duration // resolved by applyDefaults — read this
	touchDebounce    time.Duration

	tokenTTL time.Duration

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
	disableCSRFToken           bool
	allowHTTPURLsOpt           *bool // consumer intent; nil = derive
	allowHTTPURLs              bool  // resolved by applyDefaults — read this
	rateLimit                  *ratelimit.Config
	rateLimitStoreExplicit     bool // true once WithRateLimitStore/WithRateLimit sets Store — that Store is the consumer's, Close() must not touch it
	csrfToken                  *middleware.CSRFTokenConfig

	requireEmail2FA                  bool
	defaultTwoFactorEnabled          bool
	twoFactorCodeTTL                 time.Duration
	disableTwoFactorChallengeBinding bool
	twoFactorChallengeCookieName     string
	disableAdminTwoFactor            bool

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

// Option configures a config. It is an alias rather than a defined type so
// that the With* functions keep returning the same underlying signature, and
// consumers can name it — `[]goauth.Option{...}` — to build option sets
// conditionally. Naming the option type does not weaken the guarantee above:
// Config's fields stay unexported, so NewConfig remains the only way to
// produce a value New() accepts.
type Option = func(*Config)

// NewConfig applies the given option functions to a default config and
// validates the result. If validation fails, the returned error includes
// all invalid fields. This is the only way to produce a config that New()
// will accept — see the config type's doc comment.
func NewConfig(opts ...Option) (*Config, error) {
	var cfg Config
	for _, opt := range opts {
		opt(&cfg)
	}
	cfg.applyDefaults()
	if err := (&cfg).validate(); err != nil {
		return nil, err
	}
	cfg.validated = true
	return &cfg, nil
}
