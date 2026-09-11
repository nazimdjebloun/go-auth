package goauth

import (
	"net/http"
	"net/url"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/mailer"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

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
// MaxOrgsPerUser (0 = default 100), and every bool, which is why sections
// whose defaults include a true bool are tracked with a *Set flag instead.
//
// VerificationResendInterval is deliberately NOT in that list: its zero value
// means unset and falls back to the 60s default below. A mail throttle that
// defaults to off is a mail-bombing vector (authenticated resend with no
// minimum interval floods the recipient's inbox at the per-IP rate limit's
// pace), so the secure default is on. Set a negative value to opt back out
// to no minimum — the service treats any non-positive interval as disabled,
// and validate() leaves negatives on this field alone.
func (c *Config) applyDefaults() {
	if c.app.Environment == "" {
		c.app.Environment = EnvironmentProd
	}

	// In dev, an unconfigured mailer defaults to the log driver instead of
	// silently no-oping every send — but only when neither WithMailer nor
	// WithEmail was called; an explicit choice is never overridden.
	if c.mailer == nil && c.email == nil && c.app.Environment.normalize() == EnvironmentDev {
		c.mailer = mailer.NewLog(c.logger)
	}

	if !c.set.registration {
		c.registration = defaultRegistration()
	}
	if c.registration.InviteTTL == 0 {
		c.registration.InviteTTL = 7 * 24 * time.Hour
	}
	if c.registration.VerificationCodeTTL == 0 {
		c.registration.VerificationCodeTTL = 15 * time.Minute
	}
	if c.registration.VerificationResendInterval == 0 {
		c.registration.VerificationResendInterval = 60 * time.Second
	}
	if c.organizations.InviteTTL == 0 {
		c.organizations.InviteTTL = 7 * 24 * time.Hour
	}

	if c.session.TTL == 0 {
		c.session.TTL = 30 * 24 * time.Hour
	}
	if c.session.IdleTTL == 0 {
		c.session.IdleTTL = 7 * 24 * time.Hour
	}
	if c.session.RefreshTokenTTL == 0 {
		c.session.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	// nil means "left unset" — apply the default. A non-nil pointer is used
	// exactly as given, including *0 to mean "off"; a negative value is
	// left as-is here for validate() to reject rather than silently
	// normalized to anything.
	if c.session.GraceWindow != nil {
		c.resolved.graceWindow = *c.session.GraceWindow
	} else {
		c.resolved.graceWindow = 5 * time.Second
	}
	if c.session.TouchDebounce != nil {
		c.resolved.touchDebounce = *c.session.TouchDebounce
	} else {
		c.resolved.touchDebounce = 5 * time.Minute
	}
	if c.session.TokenTTL == 0 {
		c.session.TokenTTL = 1 * time.Hour
	}
	if c.twoFactor.CodeTTL == 0 {
		c.twoFactor.CodeTTL = 5 * time.Minute
	}
	if c.twoFactor.ChallengeCookieName == "" {
		c.twoFactor.ChallengeCookieName = "_2fa_challenge"
	}

	if c.security.PasswordPolicy == (domain.PasswordPolicy{}) {
		c.security.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true}
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
	c.resolved.cookieSecure = c.resolveCookieSecure()

	if c.rateLimit == nil {
		c.rateLimit = ratelimit.DefaultRateLimitConfig()
	}
	// The Store is created here rather than in DefaultRateLimitConfig: that
	// function is called lazily by every WithRateLimit* option to seed a
	// config, so building a store inside it started a cleanup goroutine per
	// option call that nothing owned and Close could never reach. Building
	// it once, here, also means Store is genuinely optional — a consumer
	// passing WithRateLimit(ratelimit.Config{...}) without one gets the
	// in-memory default instead of a validation error.
	if c.rateLimit.Store == nil {
		c.rateLimit.Store = ratelimit.NewMemoryStore(ratelimit.WithStoreLogger(c.logger))
		c.set.rateLimitStore = false // we built it, so Close owns it
	}

	c.resolved.allowHTTPURLs = c.resolveAllowHTTPURLs()
}

// resolveAllowHTTPURLs honours an explicit SecurityConfig.AllowHTTPURLs and
// otherwise derives it: http:// links are acceptable in a dev environment and
// refused everywhere else.
func (c *Config) resolveAllowHTTPURLs() bool {
	if c.security.AllowHTTPURLs != nil {
		return *c.security.AllowHTTPURLs
	}
	return c.app.Environment.normalize() == EnvironmentDev
}

// resolveCookieSecure honours an explicit CookieConfig.Secure and otherwise
// derives it: secure unless the app is served over http:// in development.
func (c *Config) resolveCookieSecure() bool {
	if c.cookie.Secure != nil {
		return *c.cookie.Secure
	}
	if c.app.Environment.normalize() != EnvironmentDev {
		return true
	}
	parsed, err := url.Parse(c.app.BaseURL)
	if err != nil {
		return true
	}
	return parsed.Scheme != "http"
}
