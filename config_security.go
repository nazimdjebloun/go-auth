package goauth

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
)

// SecurityConfig groups CSRF, password, and email-link settings. Two-factor
// options moved to TwoFactorConfig — they were six of this struct's thirteen
// fields, and TOTP will add more.
type SecurityConfig struct {
	AllowedOrigins          []string                    // allowed origins for CSRF Origin/Referer check
	AllowMissingCSRFHeaders bool                        // allow requests without Origin/Referer headers (default false)
	CSRFToken               *middleware.CSRFTokenConfig // double-submit cookie CSRF (optional overrides; the layer is on by default)
	PasswordPolicy          domain.PasswordPolicy       // password complexity (zero value = MinLength 8, RequireDigit)

	// DisableCSRFToken turns off the double-submit cookie layer. Origin/Referer
	// checking still applies and cannot be disabled. Intended for deployments
	// with no browser clients — a CLI or a server-to-server API — where CSRF is
	// not part of the threat model and the token round-trip is pure friction.
	//
	// The zero value keeps the layer on: this is spelled as "Disable" rather
	// than "Enable" so that forgetting it is the secure outcome.
	DisableCSRFToken bool

	// AllowHTTPURLs permits http:// links in rendered emails. It governs
	// template rendering, not transport, so it applies to every mailer.
	//
	// Tri-state: nil (the default) derives it — allowed in EnvironmentDev,
	// refused everywhere else. Set it explicitly with AllowPlaintextEmailLinks
	// to allow plaintext links outside a dev environment, or
	// RequireHTTPSEmailLinks to enforce https:// even in development.
	AllowHTTPURLs *bool

	// PepperRotatedAt records when the current WithSecret value went live, as
	// a wall-clock time in UTC. The library HMAC-peppers low-entropy codes
	// (2FA, verification, set-password, delete-account) with a subkey derived
	// from the secret; a code issued before this timestamp was hashed under a
	// previous secret and can never verify, so it is answered expired-style
	// ("resend, don't retry") instead of invalid.
	//
	// Set it — via WithPepperRotatedAt — exactly when you rotate the secret,
	// to the moment the new secret went live, on every instance alike. It is
	// deliberately operator-set rather than derived at boot: every instance
	// behind a load balancer must agree on one value, and a boot-stamped
	// timestamp would make rolling deploys disagree per-request about which
	// codes are stale. Zero (the default, fixed epoch) disables the stale
	// branch: codes are then verified purely by HMAC, and a rotated pepper
	// surfaces as invalid_code rather than expired. Slight future skew is
	// self-correcting — codes read stale only until the timestamp passes.
	PepperRotatedAt time.Time
}

// PasswordPepperConfig configures optional, versioned password peppering.
// CurrentVersion selects the key used for new password writes. Zero disables
// peppering for new writes; Keys may still contain non-zero future versions so
// a rolling deployment can preload them before activation.
//
// Each stored password carries its exact pepper version. Keep every key whose
// version is still present in the database until startup validation reports
// that it is no longer needed.
type PasswordPepperConfig struct {
	CurrentVersion uint32
	Keys           map[uint32]string
}

// TwoFactorConfig groups the email two-factor settings, split out of
// SecurityConfig where they were six of thirteen fields.
type TwoFactorConfig struct {
	// RequireEmail2FA makes email two-factor mandatory for every password
	// login. Enable/Disable both reject while it is on, so users cannot opt
	// out. Non-admin OAuth logins are not covered — see docs/security.mdx.
	RequireEmail2FA bool

	// DefaultEnabled seeds User.TwoFactorEnabled at registration. Users can
	// still opt out with Disable; use RequireEmail2FA for the mandatory case.
	DefaultEnabled bool

	// CodeTTL is how long a 2FA login code lives (default 5m). Deliberately
	// shorter than VerificationCodeTTL: a 6-digit code has ~20 fewer bits than
	// the 8-char alphanumeric codes used elsewhere.
	CodeTTL time.Duration

	// DisableChallengeBinding turns off the challenge binding cookie, which
	// otherwise ties a 2FA challenge to the browser that started it.
	//
	// As with DisableCSRFToken, the zero value keeps the protection on: this is
	// spelled as "Disable" so that forgetting it is the secure outcome. Intended
	// for the same consumers — a CLI or server-to-server API with no browser —
	// where a mandatory cookie makes 2FA unusable. With it set, the challenge id
	// alone identifies the challenge, so treat it as a secret and keep it out of
	// logs.
	DisableChallengeBinding bool

	// ChallengeCookieName overrides the binding cookie name
	// (default "_2fa_challenge").
	ChallengeCookieName string

	// DisableAdminTwoFactor turns off the unconditional email two-factor
	// requirement for admin password/OAuth login and privileged HTTP access.
	// Intended for API-only deployments
	// with no email delivery at all — every other email-gated feature
	// (RequireEmailVerification, EnableInvite, RequireEmail2FA, DefaultEnabled)
	// must also be off before a mailer becomes optional; see NewConfig's
	// validation error if one still needs it.
	//
	// The zero value keeps admin-account 2FA on: this is spelled as "Disable"
	// so that forgetting it is the secure outcome.
	DisableAdminTwoFactor bool
}

// WithPasswordHasher provides a custom password hasher implementation,
// replacing the default (bcrypt). The stored hash's own format prefix
// (e.g. "$2a$", "$argon2id$") identifies which algorithm produced it —
// Compare must dispatch on that prefix, not on whichever hasher is
// currently configured, so hashes written under a previous hasher remain
// verifiable after this is changed. See rehash-on-login below.
func WithPasswordHasher(h port.Hasher) Option {
	return func(c *Config) {
		c.passwordHasher = h
	}
}

// WithPasswordPepper configures optional, versioned password peppering.
// CurrentVersion selects the key used for new writes; zero keeps new writes
// unpeppered. Keys may include future versions for a safe rolling rollout.
// Every configured secret must contain at least 32 bytes of independently
// managed key material. The map is copied when the option is applied.
func WithPasswordPepper(cfg PasswordPepperConfig) Option {
	return func(c *Config) {
		c.passwordPepper = cfg
		if cfg.Keys != nil {
			c.passwordPepper.Keys = make(map[uint32]string, len(cfg.Keys))
			for version, secret := range cfg.Keys {
				c.passwordPepper.Keys[version] = secret
			}
		}
	}
}

// WithBcryptCost is the narrow sugar for "stay on bcrypt, just change the
// cost" — no WithPasswordHasher(bcrypt.New(14)) call needed for a one-int
// tweak. Existing rows hashed at a different cost keep verifying (Compare
// reads the cost from each stored hash, not from the hasher), and a
// successful login against them re-hashes the password at the new cost —
// see rehash-on-login. WithPasswordHasher, being the more specific option,
// takes precedence over this one regardless of call order.
func WithBcryptCost(cost int) Option {
	return func(c *Config) {
		c.bcryptCost = cost
	}
}

// WithSecurity groups CSRF, password, and email-link settings. A zero-valued
// PasswordPolicy keeps its default — see applyDefaults. Two-factor options are
// separate: see WithTwoFactor.
func WithSecurity(cfg SecurityConfig) Option {
	return func(c *Config) {
		c.security = cfg
		// AllowedOrigins and CSRFToken are the two reference types in this
		// section, so they are copied rather than aliased: the consumer keeps
		// ownership of what they passed, and New() resolves defaults onto
		// CSRFToken in place.
		c.security.AllowedOrigins = append([]string(nil), cfg.AllowedOrigins...)
		if cfg.CSRFToken != nil {
			tok := *cfg.CSRFToken
			c.security.CSRFToken = &tok
		}
	}
}

// WithTwoFactor groups the email two-factor settings. A zero-valued CodeTTL or
// ChallengeCookieName keeps its default — see applyDefaults.
func WithTwoFactor(cfg TwoFactorConfig) Option {
	return func(c *Config) {
		c.twoFactor = cfg
	}
}

// WithSecret sets the app-wide root secret from which CSRF, OAuth, two-factor,
// and OTP keys are derived. It is required and must be at least 32 bytes for
// HMAC-SHA256. The optional password pepper is deliberately separate; enable
// it with WithPasswordPepper. Do not commit secrets to source control; supply
// them from the environment or a secrets manager.
//
// When rotating the secret, also set WithPepperRotatedAt to the moment the
// new secret went live, or in-flight low-entropy codes fail as invalid_code
// instead of expired.
func WithSecret(secret string) Option {
	return func(c *Config) {
		c.secret = secret
	}
}

// WithPepperRotatedAt records when the current WithSecret value went live
// (UTC) — set it exactly when you rotate the secret, to the same value on
// every instance. See SecurityConfig.PepperRotatedAt. Surgical on purpose:
// rotation must not require restating the rest of SecurityConfig.
func WithPepperRotatedAt(t time.Time) Option {
	return func(c *Config) {
		c.security.PepperRotatedAt = t
	}
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

// validatePasswordHasher checks the hasher settings that do not require
// invoking a consumer-supplied live object. New validates the custom hasher's
// self-identifying output and Compare behavior when it builds the registry.
// A cost below bcrypt.MinCost keeps hasher.New's existing default-cost
// behavior.
func (c *Config) validatePasswordHasher() []error {
	var errs []error
	// WithPasswordHasher is more specific and makes WithBcryptCost inert,
	// regardless of option order.
	if c.passwordHasher == nil && c.bcryptCost > bcrypt.MaxCost {
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

// boolPtr returns a pointer to v — the shared implementation behind the
// readable spellings below, for the tri-state config fields where nil means
// "derive from the environment": CookieConfig.Secure and
// SecurityConfig.AllowHTTPURLs.
func boolPtr(v bool) *bool { return &v }

// AllowPlaintextEmailLinks and RequireHTTPSEmailLinks are readable spellings
// for SecurityConfig.AllowHTTPURLs. AllowPlaintextEmailLinks permits http://
// links in emails outside a dev environment; RequireHTTPSEmailLinks enforces
// https:// even inside one.
func AllowPlaintextEmailLinks() *bool { return boolPtr(true) }

// RequireHTTPSEmailLinks requires HTTPS URLs in emails.
func RequireHTTPSEmailLinks() *bool { return boolPtr(false) }

func (c *Config) applyTwoFactorDefaults() {
	if c.twoFactor.CodeTTL == 0 {
		c.twoFactor.CodeTTL = 5 * time.Minute
	}
	if c.twoFactor.ChallengeCookieName == "" {
		c.twoFactor.ChallengeCookieName = "_2fa_challenge"
	}
}

func (c *Config) applySecurityDefaults() {
	if c.security.PasswordPolicy == (domain.PasswordPolicy{}) {
		c.security.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true}
	}
}

func (c *Config) applyEmailURLDefaults() {
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
