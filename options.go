package goauth

import (
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// WithApp configures app-level identity settings.
func WithApp(cfg AppConfig) Option {
	return func(c *Config) {
		c.app = cfg
	}
}

// WithCookie sets the cookie configuration. Fields left at their zero value
// keep their defaults — see applyDefaults.
func WithCookie(cfg CookieConfig) Option {
	return func(c *Config) {
		c.cookie = cfg
	}
}

// WithEmail configures SMTP email delivery (transport only).
func WithEmail(cfg EmailConfig) Option {
	return func(c *Config) {
		c.email = &cfg
	}
}

// WithMailer provides a custom mailer implementation.
func WithMailer(m port.Mailer) Option {
	return func(c *Config) {
		c.mailer = m
	}
}

// WithTemplates provides a custom email template provider.
// When set, the provider's Render method is called for every email instead of
// the built-in default templates.
func WithTemplates(p port.TemplateProvider) Option {
	return func(c *Config) {
		c.templates = p
	}
}

// WithPasswordHasher provides a custom password hasher implementation,
// replacing the default (bcrypt). The stored hash's own format prefix
// (e.g. "$2a$", "$argon2id$") identifies which algorithm produced it —
// Compare must dispatch on that prefix, not on whichever hasher is
// currently configured, so hashes written under a previous hasher remain
// verifiable after this is changed. See rehash-on-login below.
func WithPasswordHasher(h port.Hasher) Option {
	return func(c *Config) {
		c.PasswordHasher = h
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

// WithSession groups session lifetime settings.
func WithSession(cfg SessionConfig) Option {
	return func(c *Config) {
		c.session = cfg
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

// WithRateLimit configures rate limiting. The Routes map and TrustedIPs slice
// are deep-copied: a value parameter alone only copies the map header, so
// later WithRateLimitRoute calls would otherwise write through to the
// consumer's own map and leak across separate NewConfig calls.
func WithRateLimit(cfg ratelimit.Config) Option {
	return func(c *Config) {
		clone := cfg
		if cfg.Routes != nil {
			clone.Routes = make(map[string]ratelimit.Rate, len(cfg.Routes))
			for k, v := range cfg.Routes {
				clone.Routes[k] = v
			}
		}
		clone.TrustedIPs = append([]string(nil), cfg.TrustedIPs...)
		clone.DisabledPaths = append([]string(nil), cfg.DisabledPaths...)
		// Store and Logger are deliberately shared: they are live objects the
		// consumer owns, not data to be snapshotted.
		c.rateLimit = &clone
		// Only a Store the consumer actually supplied is theirs to own. A
		// zero Store here means applyDefaults will build one, and that one
		// is ours to close.
		c.set.rateLimitStore = cfg.Store != nil
	}
}

// WithRateLimitEnabled toggles rate limiting on/off without touching Routes, Default, or Store.
func WithRateLimitEnabled(enabled bool) Option {
	return func(c *Config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.Enabled = enabled
	}
}

// WithRateLimitDefault overrides only the fallback rate applied to routes not present in Routes.
func WithRateLimitDefault(r ratelimit.Rate) Option {
	return func(c *Config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.Default = r
	}
}

// WithRateLimitRoute overrides or adds a single route's rate without replacing the rest of the Routes table.
func WithRateLimitRoute(pattern string, r ratelimit.Rate) Option {
	return func(c *Config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		if c.rateLimit.Routes == nil {
			c.rateLimit.Routes = map[string]ratelimit.Rate{}
		}
		c.rateLimit.Routes[pattern] = r
	}
}

// WithRateLimitStore swaps the backing store (e.g. a Redis-backed Store) without touching Routes or Default.
func WithRateLimitStore(s ratelimit.Store) Option {
	return func(c *Config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.Store = s
		c.set.rateLimitStore = s != nil
	}
}

// WithTrustedIPs sets the list of IPs/CIDRs trusted to supply IPAddressHeader.
func WithTrustedIPs(ips []string) Option {
	return func(c *Config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.TrustedIPs = append([]string(nil), ips...)
	}
}

// WithIPv6Subnet sets the subnet prefix length used to bucket IPv6 clients for rate limiting.
func WithIPv6Subnet(prefixLen int) Option {
	return func(c *Config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.IPv6Subnet = prefixLen
	}
}

// WithIPAddressHeader sets which header to trust for client IP (e.g. "CF-Connecting-IP").
// Requires TrustedIPs to be set - validated in config.validate().
func WithIPAddressHeader(header string) Option {
	return func(c *Config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.IPAddressHeader = header
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Config) {
		c.logger = logger
	}
}

// WithProvider registers an OAuth provider.
// The provider's Name() must be non-empty and unique across all registered providers.
// Nil providers are rejected.
func WithProvider(p port.OAuthProvider) Option {
	return func(c *Config) {
		c.providers = append(c.providers, p)
	}
}

// WithAudit configures audit logging. Sinks listed in cfg are registered once
// regardless of how many times this option is applied; appending them here
// instead would duplicate every sink — and so every audit event — on a repeat
// call. New() reads cfg.Sinks and the WithAuditSink list together.
func WithAudit(cfg AuditConfig) Option {
	return func(c *Config) {
		c.audit = cfg
	}
}

// WithAuditSink adds a custom audit event sink (e.g. Kafka, NATS, webhook).
// Only takes effect when audit is enabled via WithAudit.
func WithAuditSink(sink audit.EventSink) Option {
	return func(c *Config) {
		c.auditSinks = append(c.auditSinks, sink)
	}
}
