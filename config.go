package goauth

import (
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
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
	// Consumer intent — exactly what the With* options were handed, unmodified.
	// Never read a field here that has a twin in resolved; read the twin.
	app           AppConfig
	session       SessionConfig
	security      SecurityConfig
	twoFactor     TwoFactorConfig
	cookie        CookieConfig
	registration  RegistrationConfig
	organizations OrganizationConfig
	audit         AuditConfig
	email         *EmailConfig
	secret        string // app-wide HMAC signing key; signers MUST fail closed on empty (see csrf_token.go) — validate() only guards NewConfig

	// Live objects the consumer supplied, not data to snapshot.
	mailer     port.Mailer
	templates  port.TemplateProvider
	providers  []port.OAuthProvider
	auditSinks []audit.EventSink
	logger     *slog.Logger
	rateLimit  *ratelimit.Config

	resolved resolved
	set      sectionsSet
}

// resolved holds every value applyDefaults computed, kept apart from the
// intent fields above so the distinction is structural rather than a comment
// asking a reader not to touch the neighbouring field.
//
// The rule for what lands here: a setting whose zero value is a legitimate
// choice needs both an intent field (a pointer, so nil means "unset") and a
// resolved twin — 0 is a real GraceWindow ("off") and false is a real
// cookie Secure. A setting whose zero value can only mean "unset" is simply
// defaulted in place and never appears here, which is why TTLs do not.
type resolved struct {
	graceWindow   time.Duration // from session.GraceWindow (nil = 5s)
	touchDebounce time.Duration // from session.TouchDebounce (nil = 5m)
	allowHTTPURLs bool          // from security.AllowHTTPURLs (nil = dev only)
	cookieSecure  bool          // from cookie.Secure (nil = derived from BaseURL and Environment)

	// validated is set only by NewConfig() after validate() succeeds. New()
	// checks it, which is what stops a hand-built &Config{} — the fields are
	// unexported, so such a value can never be populated, only passed.
	validated bool
}

// sectionsSet records which sections the consumer actually called an option
// for. Bool fields have no "unset" state, so a section-level default can only
// be applied to a section nobody touched — see applyDefaults.
type sectionsSet struct {
	registration   bool
	rateLimitStore bool // true once WithRateLimitStore/WithRateLimit set a Store — that Store is the consumer's, Close() must not touch it
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
	cfg.resolved.validated = true
	return &cfg, nil
}

// clone returns a deep copy of c that shares only live objects the consumer
// owns (DB handles, mailer, templates, providers, logger, rate-limit store).
// Every value New() resolves defaults onto is copied, so reusing one *Config
// for two New() calls cannot leak the first call's resolutions into the
// second — notably CSRFToken (mutated in place by applyCSRFTokenDefaults),
// rateLimit.Logger, and the driver/database opened flags.
func (c *Config) clone() Config {
	cfg := *c

	if c.security.AllowedOrigins != nil {
		cfg.security.AllowedOrigins = append([]string(nil), c.security.AllowedOrigins...)
	}
	if c.security.CSRFToken != nil {
		tok := *c.security.CSRFToken
		cfg.security.CSRFToken = &tok
	}
	if c.security.AllowHTTPURLs != nil {
		v := *c.security.AllowHTTPURLs
		cfg.security.AllowHTTPURLs = &v
	}
	if c.session.GraceWindow != nil {
		v := *c.session.GraceWindow
		cfg.session.GraceWindow = &v
	}
	if c.session.TouchDebounce != nil {
		v := *c.session.TouchDebounce
		cfg.session.TouchDebounce = &v
	}
	if c.cookie.Secure != nil {
		v := *c.cookie.Secure
		cfg.cookie.Secure = &v
	}
	if c.email != nil {
		e := *c.email
		cfg.email = &e
	}
	if c.rateLimit != nil {
		rl := *c.rateLimit
		if c.rateLimit.Routes != nil {
			rl.Routes = make(map[string]ratelimit.Rate, len(c.rateLimit.Routes))
			for k, v := range c.rateLimit.Routes {
				rl.Routes[k] = v
			}
		}
		rl.TrustedIPs = append([]string(nil), c.rateLimit.TrustedIPs...)
		rl.DisabledPaths = append([]string(nil), c.rateLimit.DisabledPaths...)
		// Store and Logger are live objects — shared, not snapshotted.
		cfg.rateLimit = &rl
	}
	cfg.providers = append([]port.OAuthProvider(nil), c.providers...)
	cfg.auditSinks = append([]audit.EventSink(nil), c.auditSinks...)
	if c.audit.Sinks != nil {
		cfg.audit.Sinks = append([]audit.EventSink(nil), c.audit.Sinks...)
	}

	return cfg
}
