package goauth

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/port"
)

// SecurityConfig groups password, email-change, email-link, and secret rotation policy.
// Browser transport belongs to BrowserConfig; two-factor policy to TwoFactorConfig.
type SecurityConfig struct {
	PasswordPolicy domain.PasswordPolicy // zero value = 8..128 characters, RequireLetter and RequireDigit

	// AllowEmailChange enables self-service email changes with confirmation
	// from both mailboxes. Disabled by default; a configured mailer is required.
	AllowEmailChange bool

	// AllowHTTPURLs permits http:// links in rendered emails. It governs
	// template rendering, not transport, so it applies to every mailer.
	//
	// Tri-state: nil (the default) derives it — allowed in EnvironmentDev,
	// refused everywhere else. Set it explicitly with AllowPlaintextEmailLinks
	// to allow plaintext links outside a dev environment, or
	// RequireHTTPSEmailLinks to enforce https:// even in development.
	AllowHTTPURLs *bool

	// SecretRotatedAt records the UTC time the current WithSecret value became
	// active. Set it in WithSecurity when rotating that secret, using the same
	// value on every instance, never each instance's boot time.
	//
	// It classifies older low-entropy codes as stale before HMAC comparison
	// where the flow can locate the stored challenge. Email verification first
	// looks up the submitted code's current-pepper hash, so an old-secret code
	// still returns code_invalid. Zero (the default) disables timestamp-based
	// expiry classification. This metadata does not rotate any key and is
	// unrelated to versioned password peppering.
	SecretRotatedAt time.Time
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

// TwoFactorConfig controls email two-factor policy and code lifetime.
type TwoFactorConfig struct {
	// RequireEmail2FA makes email two-factor mandatory after password or OAuth
	// authentication. Enable/Disable both reject while it is on, so users
	// cannot opt out.
	RequireEmail2FA bool

	// DefaultEnabled seeds User.TwoFactorEnabled at registration. Users can
	// still opt out with Disable; use RequireEmail2FA for the mandatory case.
	DefaultEnabled bool

	// CodeTTL is how long a 2FA login code lives (default 5m). Deliberately
	// shorter than VerificationCodeTTL: a 6-digit code has ~20 fewer bits than
	// the 8-char alphanumeric codes used elsewhere.
	CodeTTL time.Duration

	// DisableAdminTwoFactor turns off the unconditional email two-factor
	// requirement for admin password/OAuth login and privileged HTTP access.
	// Intended for API-only deployments
	// with no email delivery at all — every other email-gated feature
	// (RequireEmailVerification, InviteSignup, RequireEmail2FA, DefaultEnabled)
	// must also be off before a mailer becomes optional; see NewConfig's
	// validation error if one still needs it.
	//
	// The zero value keeps admin-account 2FA on: this is spelled as "Disable"
	// so that forgetting it is the secure outcome.
	DisableAdminTwoFactor bool
}

// WithSecurity groups password, email-change, email-link and secret-rotation settings. A zero-valued
// PasswordPolicy keeps its default — see applyDefaults. Two-factor options are
// separate: see WithTwoFactor. Each call replaces the whole security group.
func WithSecurity(cfg SecurityConfig) Option {
	return func(c *Config) {
		c.security = cfg

	}
}

// WithTwoFactor groups the email two-factor settings. A zero CodeTTL keeps its
// default. Browser cookie settings, including challenge names, use WithBrowser.
func WithTwoFactor(cfg TwoFactorConfig) Option {
	return func(c *Config) {
		c.twoFactor = cfg
	}
}

// WithSecret sets the app-wide root secret from which CSRF, OAuth, two-factor,
// and OTP keys are derived. It is required and must be at least 32 bytes for
// HMAC-SHA256. The optional password pepper is deliberately separate; enable
// it with PasswordHashingConfig.Pepper. Do not commit secrets to source control; supply
// them from the environment or a secrets manager.
//
// When rotating the secret, also set SecurityConfig.SecretRotatedAt in
// WithSecurity to the moment the new secret became active. See that field for
// how the timestamp classifies in-flight low-entropy codes.
func WithSecret(secret string) Option {
	return func(c *Config) {
		c.secret = secret
	}
}

func (c *Config) validateSecurity() []error {
	var errs []error
	if err := c.security.PasswordPolicy.ValidateConfig(); err != nil {
		errs = append(errs, fmt.Errorf("password_policy: %w", err))
	}
	limit, err := passwordInputLimit(c.passwordHasher)
	if err != nil {
		errs = append(errs, err)
	} else if limit > 0 {
		if c.passwordPepper.CurrentVersion == 0 && c.security.PasswordPolicy.MinLength > limit {
			errs = append(errs, fmt.Errorf("password_policy: MinLength cannot fit the selected hasher's %d-byte input limit", limit))
		}
		if c.passwordPepper.CurrentVersion != 0 && limit < 44 {
			errs = append(errs, errors.New("password_hasher: input limit cannot fit the 44-byte password-pepper representation"))
		}
	}
	if len(c.secret) == 0 {
		errs = append(errs, errors.New("secret: signing secret is required"))
	} else if len(c.secret) < 32 {
		errs = append(errs, errors.New("secret: signing secret must be at least 32 bytes for HMAC-SHA256"))
	}

	return errs
}

func passwordInputLimit(h port.Hasher) (int, error) {
	if h == nil {
		return hasher.BcryptMaxPasswordBytes, nil
	}
	value := reflect.ValueOf(h)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return 0, errors.New("password_hasher: hasher is nil")
		}
	}
	limit := 0
	if limiter, ok := h.(port.PasswordInputLimiter); ok {
		limit = limiter.MaxPasswordBytes()
	}
	if limit < 0 {
		return 0, errors.New("password_hasher: MaxPasswordBytes must be nonnegative")
	}
	return limit, nil
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
	if c.passwordConcurrency < 0 {
		errs = append(errs, errors.New("password_concurrency must be nonnegative"))
	}
	if c.passwordWorkLimiter != nil && c.passwordWorkLimiter.Limit() == 0 {
		errs = append(errs, errors.New("password_work_limiter must be constructed with hasher.NewWorkLimiter"))
	}
	// A custom Hasher makes PasswordHashingConfig.BcryptCost inert.
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
}

func (c *Config) applySecurityDefaults() {
	c.security.PasswordPolicy = c.security.PasswordPolicy.WithDefaults()
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
