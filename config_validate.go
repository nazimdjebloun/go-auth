package goauth

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/nazimdjebloun/go-auth/mailer"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

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
	if c.requireEmail2FA {
		reasons = append(reasons, "RequireEmail2FA")
	}
	if c.defaultTwoFactorEnabled {
		reasons = append(reasons, "DefaultTwoFactorEnabled")
	}
	if !c.disableAdminTwoFactor {
		reasons = append(reasons, "AdminLogin two-factor (set DisableAdminTwoFactor to opt out)")
	}
	return reasons
}

func (c *Config) validate() error {
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
	// A resolved value can only be negative here if the consumer explicitly
	// set GraceWindow/TouchDebounce to a negative *time.Duration — nil
	// (unset) resolves to the positive default, and 0 (off) is never
	// negative, so there's no "meant to disable it" case to special-case.
	if c.graceWindow < 0 {
		errs = append(errs, errors.New("session grace_window must not be negative (use goauth.Duration(0) to turn it off)"))
	}
	if c.touchDebounce < 0 {
		errs = append(errs, errors.New("session touch_debounce must not be negative (use goauth.Duration(0) to turn it off)"))
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
	if c.disableCSRFToken && c.allowMissingCSRFHeaders {
		errs = append(errs, errors.New(
			"security: DisableCSRFToken and AllowMissingCSRFHeaders cannot both be set — "+
				"a cross-site request with no Origin/Referer and no token would pass; keep one of the two layers"))
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

	if _, isLog := c.mailer.(*mailer.Log); isLog && c.environment.normalize() != EnvironmentDev {
		errs = append(errs, errors.New("mailer: mailer.Log cannot be used outside EnvironmentDev — codes and reset links would be written to application logs instead of delivered"))
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
		if e.TLS < TLSStart || e.TLS > TLSNone {
			errs = append(
				errs,
				fmt.Errorf("email: tls mode must be one of TLSNone, TLSStart, or TLSImplicit, got %d", e.TLS),
			)
		}
	}
	// A mailer is required only if some configured feature actually sends
	// email — see requiresMailer. AdminLogin's two-factor challenge is on by
	// default (see docs/security.mdx), so it's the common reason; set
	// DisableAdminTwoFactor to drop it for an API-only deployment with every
	// other email feature also off.
	if c.mailer == nil && c.email == nil {
		if reasons := c.mailerReasons(); len(reasons) > 0 {
			errs = append(errs, fmt.Errorf("email: Mailer or Email config required — enabled features need it: %s", strings.Join(reasons, ", ")))
		}
	}
	if c.registration.InviteTTL <= 0 {
		errs = append(errs, errors.New("registration: invite_ttl must be positive"))
	}
	if c.registration.VerificationCodeTTL <= 0 {
		errs = append(errs, errors.New("registration: verification_code_ttl must be positive"))
	}
	if c.twoFactorCodeTTL <= 0 {
		errs = append(errs, errors.New("security: two_factor_code_ttl must be positive"))
	}
	if c.requireEmail2FA && !c.registration.EnableEmailPassword {
		errs = append(errs, errors.New("security: RequireEmail2FA has no effect when EnableEmailPassword is disabled — every gated path is a password path"))
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
		if rl.IPAddressHeader != "" && len(rl.TrustedIPs) == 0 {
			errs = append(errs, errors.New("rate_limit: ip_address_header is set but trusted_ips is empty - client-supplied header can be spoofed to bypass rate limiting"))
		}
	}

	// SameSite=None without Secure is rejected outright by every current
	// browser, so this pairing does not produce a weaker session — it
	// produces no session at all, from the first request, with nothing in the
	// server logs to explain why. Catching it here beats debugging it as
	// "login succeeds but the user is never logged in".
	if c.cookie.SameSite == http.SameSiteNoneMode && !c.cookieSecure {
		errs = append(errs, errors.New("cookie: same_site=None requires a secure cookie - browsers reject SameSite=None without Secure; use an https:// BaseURL or goauth.SecureAlways()"))
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

// validateRate checks one entry of the rate table.
//
// allowZero exists because Requests == 0 has always meant "don't limit this
// route" in the middleware and in the docs, but validate rejected it outright
// — so the documented per-route opt-out was unreachable. It's accepted for a
// Routes entry and still rejected for Default, where a zero has no such
// reading: it would silently disable limiting on every unlisted route, which
// is what WithRateLimitEnabled(false) is for.
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
