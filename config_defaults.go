package goauth

// applyDefaults fills every field the consumer left unset. It runs in
// NewConfig after all options have been applied, which is the only point at
// which "unset" is knowable: an option that assigns a struct wholesale cannot
// tell a zero field from an omitted one, so seeding defaults *before* options
// run means any partially-filled struct silently destroys them.
//
// The rule is: zero means unset. Fields where zero is a meaningful value are
// left alone by the section helpers — MaxLifetime (0 = no limit),
// MaxOrgsPerUser (0 = default 100), and every bool, which is why sections
// whose defaults include a true bool are tracked with a *Set flag instead.
//
// VerificationResendInterval is deliberately NOT in that list: its zero value
// means unset and falls back to the 60s default in applyRegistrationDefaults.
// A mail throttle that
// defaults to off is a mail-bombing vector (authenticated resend with no
// minimum interval floods the recipient's inbox at the per-IP rate limit's
// pace), so the secure default is on. Set a negative value to opt back out
// to no minimum — the service treats any non-positive interval as disabled,
// and validate() leaves negatives on this field alone.
func (c *Config) applyDefaults() {
	c.applyAppDefaults()
	c.applyMailerDefaults()
	c.applyRegistrationDefaults()
	c.applyOrganizationDefaults()
	c.applySessionDefaults()
	c.applyTwoFactorDefaults()
	c.applySecurityDefaults()
	c.applyCookieDefaults()
	c.applyRateLimitDefaults()
	c.applyEmailURLDefaults()
}
