package goauth

import (
	"errors"
	"time"
)

// RegistrationConfig controls which registration methods are available.
// Login is ALWAYS unconditional regardless of these flags.
type RegistrationConfig struct {
	EnableEmailPassword        bool          // email+password registration (default true)
	EnableOAuth                bool          // OAuth signup for new users (default true)
	EnableInvite               bool          // invite-code registration (default false; requires a mailer)
	AllowPublic                bool          // public registration is allowed (default true)
	RequireEmailVerification   bool          // require email verification on signup (default false)
	InviteTTL                  time.Duration // how long signup invites last (default 7d)
	VerificationCodeTTL        time.Duration // how long verification codes live (default 15m)
	VerificationResendInterval time.Duration // minimum interval between verification resends (default 60s; negative = no minimum)
}

// OrganizationConfig controls the organizations feature.
type OrganizationConfig struct {
	Enable         bool          // enable orgs feature (default false)
	MaxOrgsPerUser int           // max orgs a user can own (0=default 100, >100 rejected)
	InviteTTL      time.Duration // how long org invites last (default 7d)
}

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

func (c *Config) applyRegistrationDefaults() {
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
}

func (c *Config) applyOrganizationDefaults() {
	if c.organizations.InviteTTL == 0 {
		c.organizations.InviteTTL = 7 * 24 * time.Hour
	}
}

// WithRegistration configures which registration methods are available.
// Login is ALWAYS unconditional regardless of these settings.
//
// Calling this replaces the default registration settings wholesale rather
// than merging into them — the bool fields have no "unset" state, so an
// omitted flag is indistinguishable from a deliberate false. Enable every
// method you want; only the TTLs fall back to defaults when left at zero.
func WithRegistration(cfg RegistrationConfig) Option {
	return func(c *Config) {
		c.registration = cfg
		c.set.registration = true
	}
}

// WithOrganizations configures the organizations feature.
func WithOrganizations(cfg OrganizationConfig) Option {
	return func(c *Config) {
		c.organizations = cfg
	}
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
