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
// MaxOrgsPerUser (0 = default 100), VerificationResendInterval (0 = no
// minimum), and every bool, which is why sections whose defaults include a
// true bool are tracked with a *Set flag instead.
func (c *Config) applyDefaults() {
	if c.environment == "" {
		c.environment = EnvironmentProd
	}

	// In dev, an unconfigured mailer defaults to the log driver instead of
	// silently no-oping every send — but only when neither WithMailer nor
	// WithEmail was called; an explicit choice is never overridden.
	if c.mailer == nil && c.email == nil && c.environment.normalize() == EnvironmentDev {
		c.mailer = mailer.NewLog(c.logger)
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
	// nil means "left unset" — apply the default. A non-nil pointer is used
	// exactly as given, including *0 to mean "off"; a negative value is
	// left as-is here for validate() to reject rather than silently
	// normalized to anything.
	if c.graceWindowOpt != nil {
		c.graceWindow = *c.graceWindowOpt
	} else {
		c.graceWindow = 5 * time.Second
	}
	if c.touchDebounceOpt != nil {
		c.touchDebounce = *c.touchDebounceOpt
	} else {
		c.touchDebounce = 5 * time.Minute
	}
	if c.tokenTTL == 0 {
		c.tokenTTL = 1 * time.Hour
	}
	if c.twoFactorCodeTTL == 0 {
		c.twoFactorCodeTTL = 5 * time.Minute
	}
	if c.twoFactorChallengeCookieName == "" {
		c.twoFactorChallengeCookieName = "_2fa_challenge"
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
	// The Store is created here rather than in DefaultRateLimitConfig: that
	// function is called lazily by every WithRateLimit* option to seed a
	// config, so building a store inside it started a cleanup goroutine per
	// option call that nothing owned and Close could never reach. Building
	// it once, here, also means Store is genuinely optional — a consumer
	// passing WithRateLimit(ratelimit.Config{...}) without one gets the
	// in-memory default instead of a validation error.
	if c.rateLimit.Store == nil {
		c.rateLimit.Store = ratelimit.NewMemoryStore(ratelimit.WithStoreLogger(c.logger))
		c.rateLimitStoreExplicit = false // we built it, so Close owns it
	}

	c.allowHTTPURLs = c.resolveAllowHTTPURLs()
}

// resolveAllowHTTPURLs honours an explicit SecurityConfig.AllowHTTPURLs and
// otherwise derives it: http:// links are acceptable in a dev environment and
// refused everywhere else.
func (c *Config) resolveAllowHTTPURLs() bool {
	if c.allowHTTPURLsOpt != nil {
		return *c.allowHTTPURLsOpt
	}
	return c.environment.normalize() == EnvironmentDev
}

// resolveCookieSecure honours an explicit CookieConfig.Secure and otherwise
// derives it: secure unless the app is served over http:// in development.
func (c *Config) resolveCookieSecure() bool {
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
