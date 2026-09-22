package goauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"

	"github.com/nazimdjebloun/go-auth/mailer"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// validate reports every problem with the config at once rather than the
// first, so a consumer fixes one round of errors instead of N.
//
// The checks are grouped by the config section they read, with one exception:
// validateCoherence holds the rules where each field is individually valid but
// the combination is wrong. Those are the ones that catch real deployment
// mistakes — a CSRF layer disabled on both sides, a cookie no browser will
// store — and keeping them together makes them auditable instead of buried
// among thirty "must be positive" checks.
func (c *Config) validate() error {
	var errs []error
	for _, check := range []func() []error{
		c.validateApp,
		c.validateDatabase,
		c.validateSession,
		c.validateCookie,
		c.validateSecurity,
		c.validateTwoFactor,
		c.validateMailer,
		c.validateRegistration,
		c.validateOrganizations,
		c.validateMaintenance,
		c.validateRateLimit,
		c.validateProviders,
		c.validatePasswordHasher,
		c.validateCoherence,
	} {
		errs = append(errs, check()...)
	}
	return errors.Join(errs...)
}

func (c *Config) validateApp() []error {
	var errs []error
	if c.app.Name == "" {
		errs = append(errs, errors.New("app_name cannot be empty"))
	}
	if c.app.BaseURL == "" {
		errs = append(errs, errors.New("base_url is required"))
	} else if parsedURL, err := url.Parse(c.app.BaseURL); err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		errs = append(errs, errors.New("base_url must be a valid HTTP or HTTPS URL"))
	}
	switch c.app.Environment.normalize() {
	case EnvironmentDev, EnvironmentStaging, EnvironmentProd:
	default:
		errs = append(errs, fmt.Errorf("environment must be one of dev, staging, or prod, got %q", c.app.Environment))
	}
	return errs
}

func (c *Config) validateDatabase() []error {
	var errs []error
	if _, _, err := c.app.Database.connectionLimits(); err != nil {
		errs = append(errs, err)
	}
	if c.app.Database.Driver == "" {
		errs = append(errs, errors.New("database: driver cannot be empty"))
	}
	if c.app.Database.URL == "" && c.app.Database.DB == nil && c.app.Database.Pool == nil {
		errs = append(errs, errors.New("database: one of URL, DB, or Pool is required"))
	}
	return errs
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

func (c *Config) validateSecurity() []error {
	var errs []error
	if len(c.secret) == 0 {
		errs = append(errs, errors.New("secret: signing secret is required"))
	} else if len(c.secret) < 32 {
		errs = append(errs, errors.New("secret: signing secret must be at least 32 bytes for HMAC-SHA256"))
	}
	if len(c.security.AllowedOrigins) == 0 {
		errs = append(errs, errors.New("allowed_origins must include at least one origin"))
	}
	for _, o := range c.security.AllowedOrigins {
		if o == "*" {
			errs = append(errs, errors.New("allowed_origins must not contain \"*\" — this disables CSRF protection; list specific origins instead"))
		}
	}
	return errs
}

func (c *Config) validateTwoFactor() []error {
	var errs []error
	if c.twoFactor.CodeTTL <= 0 {
		errs = append(errs, errors.New("two_factor: code_ttl must be positive"))
	}
	return errs
}

func (c *Config) validateMailer() []error {
	var errs []error
	// SMTP fields only matter when go-auth builds the mailer itself; a custom
	// Mailer owns its own transport config.
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
		if e.TLS < TLSStart || e.TLS > TLSNone {
			errs = append(
				errs,
				fmt.Errorf("email: tls mode must be one of TLSNone, TLSStart, or TLSImplicit, got %d", e.TLS),
			)
		}
		if e.TLS == TLSNone && c.app.Environment.normalize() != EnvironmentDev {
			errs = append(errs, errors.New("email: TLSNone is only allowed in EnvironmentDev — use TLSStart or TLSImplicit outside development"))
		}
	}
	return errs
}

func (c *Config) validateRegistration() []error {
	var errs []error
	if c.registration.InviteTTL <= 0 {
		errs = append(errs, errors.New("registration: invite_ttl must be positive"))
	}
	if c.registration.VerificationCodeTTL <= 0 {
		errs = append(errs, errors.New("registration: verification_code_ttl must be positive"))
	}
	return errs
}

func (c *Config) validateOrganizations() []error {
	var errs []error
	if !c.organizations.Enable {
		return nil
	}
	if c.organizations.MaxOrgsPerUser < 0 || c.organizations.MaxOrgsPerUser > 100 {
		errs = append(errs, errors.New("organizations.max_orgs_per_user must be between 0 and 100 (0 = default 100)"))
	}
	if c.organizations.InviteTTL <= 0 {
		errs = append(errs, errors.New("organizations.invite_ttl must be positive"))
	}
	return errs
}

func (c *Config) validateRateLimit() []error {
	var errs []error
	if c.rateLimit == nil || !c.rateLimit.Enabled {
		return nil
	}
	rl := c.rateLimit
	// Store is not checked: applyDefaults runs first and fills in the
	// in-memory default whenever it's nil, so "enabled with no store" is
	// no longer a reachable configuration.
	if err := validateRate("default", rl.Default, false); err != nil {
		errs = append(errs, err)
	}
	for route, rate := range rl.Routes {
		if err := validateRate(route, rate, true); err != nil {
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
	return errs
}

func (c *Config) validateProviders() []error {
	var errs []error
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
		if cfg, ok := p.(interface{ OAuth2Config() *oauth2.Config }); ok {
			c := cfg.OAuth2Config()
			if c.ClientID == "" {
				errs = append(errs, fmt.Errorf("provider %q: client_id is required", name))
			}
			if c.ClientSecret == "" {
				errs = append(errs, fmt.Errorf("provider %q: client_secret is required", name))
			}
		}
	}
	return errs
}

// validatePasswordHasher checks the hasher settings that do not require
// invoking a consumer-supplied live object. New validates the custom hasher's
// self-identifying output and Compare behavior when it builds the registry.
// A cost below bcrypt.MinCost keeps hasher.New's existing default-cost
// behavior.
func (c *Config) validatePasswordHasher() []error {
	var errs []error
	// WithPasswordHasher is more specific and makes WithBcryptCost inert,
	// regardless of option order.
	if c.PasswordHasher == nil && c.bcryptCost > bcrypt.MaxCost {
		errs = append(errs, fmt.Errorf("bcrypt_cost %d exceeds bcrypt.MaxCost (%d)", c.bcryptCost, bcrypt.MaxCost))
	}
	if err := c.validatePasswordPepper(); err != nil {
		errs = append(errs, err)
	}
	return errs
}

func (c *Config) validatePasswordPepper() error {
	versions := make([]uint32, 0, len(c.passwordPepper.Keys))
	for version := range c.passwordPepper.Keys {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, version := range versions {
		if version == 0 {
			return errors.New("password_pepper: key version 0 is reserved for unpeppered passwords")
		}
		if len(c.passwordPepper.Keys[version]) < 32 {
			return fmt.Errorf("password_pepper: key version %d must be at least 32 bytes", version)
		}
	}
	if c.passwordPepper.CurrentVersion != 0 {
		if _, ok := c.passwordPepper.Keys[c.passwordPepper.CurrentVersion]; !ok {
			return fmt.Errorf("password_pepper: current version %d has no configured key", c.passwordPepper.CurrentVersion)
		}
	}
	return nil
}

// validateCoherence holds every rule where each field involved is individually
// valid but the combination is not. They live together because they are the
// checks worth auditing as a set: each one describes a deployment that starts
// up, looks configured, and is broken or unsafe in a way that reads as a bug in
// this library rather than a config mistake.
//
// A new option that interacts with an existing one belongs here, not in its own
// section's function.
func (c *Config) validateCoherence() []error {
	var errs []error

	// Both CSRF layers off at once. Either alone is a supported posture; the
	// pair means a cross-site request with no Origin/Referer and no token is
	// accepted.
	if c.security.DisableCSRFToken && c.security.AllowMissingCSRFHeaders {
		errs = append(errs, errors.New(
			"security: DisableCSRFToken and AllowMissingCSRFHeaders cannot both be set — "+
				"a cross-site request with no Origin/Referer and no token would pass; keep one of the two layers"))
	}

	// SameSite=None without Secure is rejected outright by every current
	// browser, so this pairing does not produce a weaker session — it
	// produces no session at all, from the first request, with nothing in the
	// server logs to explain why. Catching it here beats debugging it as
	// "login succeeds but the user is never logged in".
	if c.cookie.SameSite == http.SameSiteNoneMode && !c.resolved.cookieSecure {
		errs = append(errs, errors.New("cookie: same_site=None requires a secure cookie - browsers reject SameSite=None without Secure; use an https:// BaseURL or goauth.SecureAlways()"))
	}

	// The log mailer writes codes and reset links to the application log
	// instead of delivering them, which is a development convenience and a
	// credential leak anywhere else.
	if _, isLog := c.mailer.(*mailer.Log); isLog && c.app.Environment.normalize() != EnvironmentDev {
		errs = append(errs, errors.New("mailer: mailer.Log cannot be used outside EnvironmentDev — codes and reset links would be written to application logs instead of delivered"))
	}

	// A mailer is required only if some configured feature actually sends
	// email — see mailerReasons. AdminLogin's two-factor challenge is on by
	// default (see docs/security.mdx), so it's the common reason; set
	// DisableAdminTwoFactor to drop it for an API-only deployment with every
	// other email feature also off.
	if c.mailer == nil && c.email == nil {
		if reasons := c.mailerReasons(); len(reasons) > 0 {
			errs = append(errs, fmt.Errorf("email: Mailer or Email config required — enabled features need it: %s", strings.Join(reasons, ", ")))
		}
	}

	// Options that gate a path no enabled feature can reach. Each is a no-op
	// rather than a danger, but a consumer who set one believes it is doing
	// something.
	if c.twoFactor.RequireEmail2FA && !c.registration.EnableEmailPassword {
		errs = append(errs, errors.New("two_factor: RequireEmail2FA has no effect when EnableEmailPassword is disabled — every gated path is a password path"))
	}
	if c.registration.RequireEmailVerification && !c.registration.EnableEmailPassword && !c.registration.EnableOAuth {
		errs = append(errs, errors.New("registration: RequireEmailVerification has no effect when both EnableEmailPassword and EnableOAuth are disabled"))
	}
	if c.registration.AllowPublic && !c.registration.EnableEmailPassword && !c.registration.EnableOAuth && !c.registration.EnableInvite {
		errs = append(errs, errors.New("registration: AllowPublic is true but no registration method is enabled"))
	}

	// A forwarding header is only as trustworthy as the hop that set it.
	// Honouring one with no trusted peers lets any client pick its own
	// rate-limit bucket.
	if c.rateLimit != nil && c.rateLimit.Enabled &&
		c.rateLimit.IPAddressHeader != "" && len(c.rateLimit.TrustedIPs) == 0 {
		errs = append(errs, errors.New("rate_limit: ip_address_header is set but trusted_ips is empty - client-supplied header can be spoofed to bypass rate limiting"))
	}

	return errs
}

// mailerReasons lists which enabled features require a Mailer or Email
// config, by the exported field name a consumer would recognize. Empty means
// no configured feature sends email, so the mailer is genuinely optional.
func (c *Config) mailerReasons() []string {
	var reasons []string
	if c.registration.EnableInvite {
		reasons = append(reasons, "EnableInvite")
	}
	if c.registration.RequireEmailVerification {
		reasons = append(reasons, "RequireEmailVerification")
	}
	if c.twoFactor.RequireEmail2FA {
		reasons = append(reasons, "RequireEmail2FA")
	}
	if c.twoFactor.DefaultEnabled {
		reasons = append(reasons, "DefaultEnabled")
	}
	if !c.twoFactor.DisableAdminTwoFactor {
		reasons = append(reasons, "AdminLogin two-factor (set DisableAdminTwoFactor to opt out)")
	}
	return reasons
}

func validateRate(name string, r ratelimit.Rate, allowZero bool) error {
	if r.Requests < 0 || (r.Requests == 0 && !allowZero) {
		return fmt.Errorf("rate_limit: route %q requests must be positive, got %d", name, r.Requests)
	}
	if r.Requests == 0 {
		return nil // explicitly disabled; Window is irrelevant
	}
	if r.Window <= 0 {
		return fmt.Errorf("rate_limit: route %q window must be positive, got %s", name, r.Window)
	}
	return nil
}
