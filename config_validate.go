package goauth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nazimdjebloun/go-auth/mailer"
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
		c.validateBrowser,
		c.validateSecurity,
		c.validateTwoFactor,
		c.validateMailer,
		c.validateRegistration,
		c.validateOrganizations,
		c.validateAppPermissions,
		c.validateOrgPermissions,
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
