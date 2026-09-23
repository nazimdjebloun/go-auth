package goauth

import (
	"errors"
	"net/http"
	"net/url"
	"time"
)

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

// WithCookie sets the cookie configuration. Fields left at their zero value
// keep their defaults — see applyDefaults.
func WithCookie(cfg CookieConfig) Option {
	return func(c *Config) {
		c.cookie = cfg
	}
}

// WithSession groups session lifetime settings.
func WithSession(cfg SessionConfig) Option {
	return func(c *Config) {
		c.session = cfg
	}
}
func (c *Config) validateSession() []error {
	var errs []error
	if c.session.TTL <= 0 {
		errs = append(errs, errors.New("session_ttl must be positive"))
	}
	if c.session.IdleTTL <= 0 {
		errs = append(errs, errors.New("session_idle_ttl must be positive"))
	}
	if c.session.IdleTTL > c.session.TTL {
		errs = append(errs, errors.New("session_idle_ttl must not exceed session_ttl"))
	}
	if c.session.RefreshTokenTTL <= 0 {
		errs = append(errs, errors.New("refresh_token_ttl must be positive"))
	}
	if c.session.RefreshTokenTTL < c.session.TTL {
		errs = append(errs, errors.New("refresh_token_ttl must not be less than session_ttl"))
	}
	// A resolved value can only be negative here if the consumer explicitly
	// set GraceWindow/TouchDebounce to a negative *time.Duration — nil
	// (unset) resolves to the positive default, and 0 (off) is never
	// negative, so there's no "meant to disable it" case to special-case.
	if c.resolved.graceWindow < 0 {
		errs = append(errs, errors.New("session grace_window must not be negative (use goauth.Duration(0) to turn it off)"))
	}
	if c.resolved.touchDebounce < 0 {
		errs = append(errs, errors.New("session touch_debounce must not be negative (use goauth.Duration(0) to turn it off)"))
	}
	if c.session.MaxLifetime < 0 {
		errs = append(errs, errors.New("session max_lifetime must not be negative (0 = no limit)"))
	} else if c.session.MaxLifetime > 0 && c.session.MaxLifetime < c.session.TTL {
		errs = append(errs, errors.New("session max_lifetime must not be less than session_ttl"))
	}
	if c.session.TokenTTL <= 0 {
		errs = append(errs, errors.New("session token_ttl must be positive"))
	}
	return errs
}
func (c *Config) validateCookie() []error {
	var errs []error
	if c.cookie.Name == "" {
		errs = append(errs, errors.New("cookie name cannot be empty"))
	}
	return errs
}

// Duration returns a pointer to d, for SessionConfig.GraceWindow and
// SessionConfig.TouchDebounce — Go can't take the address of a duration
// literal directly. Both fields are *time.Duration rather than
// time.Duration specifically so 0 can mean "explicitly off" without
// colliding with "left unset, use the default": leave the field nil for
// the default, or set it with goauth.Duration(0) to turn the feature off,
// goauth.Duration(10*time.Second) for a custom value, and so on.
func Duration(d time.Duration) *time.Duration { return &d }

// SecureAlways and SecureNever are readable spellings for CookieConfig.Secure.
// SecureNever is for local development over http:// only — browsers will send
// the cookie over plaintext connections.
func SecureAlways() *bool { return boolPtr(true) }

// SecureNever disables secure cookies for local HTTP development.
func SecureNever() *bool { return boolPtr(false) }

func (c *Config) applySessionDefaults() {
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
}

func (c *Config) applyCookieDefaults() {
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
