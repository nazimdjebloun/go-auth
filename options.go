package goauth

import (
	"log/slog"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// WithApp configures app-level identity settings.
func WithApp(cfg AppConfig) Option {
	return func(c *config) {
		c.appName = cfg.Name
		c.baseURL = cfg.BaseURL
		c.database = cfg.Database
		c.environment = cfg.Environment
		c.verificationResendInterval = cfg.VerificationResendInterval
	}
}

// WithCookie sets the cookie configuration. Fields left at their zero value
// keep their defaults — see applyDefaults.
func WithCookie(cfg CookieConfig) Option {
	return func(c *config) {
		c.cookie = cfg
	}
}

// WithEmail configures SMTP email delivery (transport only).
func WithEmail(cfg EmailConfig) Option {
	return func(c *config) {
		c.email = &cfg
	}
}

// WithMailer provides a custom mailer implementation.
func WithMailer(m port.Mailer) Option {
	return func(c *config) {
		c.mailer = m
	}
}

// WithTemplates provides a custom email template provider.
// When set, the provider's Render method is called for every email instead of
// the built-in default templates.
func WithTemplates(p port.TemplateProvider) Option {
	return func(c *config) {
		c.templateProvider = p
	}
}

// WithSession groups session lifetime settings.
func WithSession(cfg SessionConfig) Option {
	return func(c *config) {
		c.sessionTTL = cfg.TTL
		c.sessionIdleTTL = cfg.IdleTTL
		c.refreshTokenTTL = cfg.RefreshTokenTTL
		c.maxLifetime = cfg.MaxLifetime
		c.graceWindowOpt = cfg.GraceWindow
		c.touchDebounceOpt = cfg.TouchDebounce
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
	return func(c *config) {
		c.registration = cfg
		c.registrationSet = true
	}
}

// WithOrganizations configures the organizations feature.
func WithOrganizations(cfg OrganizationConfig) Option {
	return func(c *config) {
		c.organizations = cfg
	}
}

// WithSecurity groups security-related settings. A zero-valued PasswordPolicy
// or TokenTTL keeps its default — see applyDefaults.
func WithSecurity(cfg SecurityConfig) Option {
	return func(c *config) {
		c.allowedOrigins = append([]string(nil), cfg.AllowedOrigins...)
		c.allowMissingCSRFHeaders = cfg.AllowMissingCSRFHeaders
		if cfg.CSRFToken != nil {
			tok := *cfg.CSRFToken // copy: do not alias the consumer's struct
			c.csrfToken = &tok
		}
		c.passwordPolicy = cfg.PasswordPolicy
		c.tokenTTL = cfg.TokenTTL
		c.disableCSRFToken = cfg.DisableCSRFToken
		c.allowHTTPURLsOpt = cfg.AllowHTTPURLs
		c.requireEmail2FA = cfg.RequireEmail2FA
		c.defaultTwoFactorEnabled = cfg.DefaultTwoFactorEnabled
		c.twoFactorCodeTTL = cfg.TwoFactorCodeTTL
		c.disableTwoFactorChallengeBinding = cfg.DisableTwoFactorChallengeBinding
		c.twoFactorChallengeCookieName = cfg.TwoFactorChallengeCookieName
		c.disableAdminTwoFactor = cfg.DisableAdminTwoFactor
	}
}

// WithSecret sets the app-wide signing secret. This is the first signing key
// material the library introduces and is intentionally general-purpose: it is
// used to sign CSRF tokens today and any future HMAC-based tokens this library
// adds. It is required and must be at least 32 bytes for HMAC-SHA256. Do not
// commit secrets to source control; supply it from the environment.
func WithSecret(secret string) Option {
	return func(c *config) {
		c.secret = secret
	}
}

// WithRateLimit configures rate limiting. The Routes map and TrustedIPs slice
// are deep-copied: a value parameter alone only copies the map header, so
// later WithRateLimitRoute calls would otherwise write through to the
// consumer's own map and leak across separate NewConfig calls.
func WithRateLimit(cfg ratelimit.Config) Option {
	return func(c *config) {
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
		c.rateLimitStoreExplicit = cfg.Store != nil
	}
}

// WithRateLimitEnabled toggles rate limiting on/off without touching Routes, Default, or Store.
func WithRateLimitEnabled(enabled bool) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.Enabled = enabled
	}
}

// WithRateLimitDefault overrides only the fallback rate applied to routes not present in Routes.
func WithRateLimitDefault(r ratelimit.Rate) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.Default = r
	}
}

// WithRateLimitRoute overrides or adds a single route's rate without replacing the rest of the Routes table.
func WithRateLimitRoute(pattern string, r ratelimit.Rate) Option {
	return func(c *config) {
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
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.Store = s
		c.rateLimitStoreExplicit = s != nil
	}
}

// WithTrustedIPs sets the list of IPs/CIDRs trusted to supply IPAddressHeader.
func WithTrustedIPs(ips []string) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.TrustedIPs = append([]string(nil), ips...)
	}
}

// WithIPv6Subnet sets the subnet prefix length used to bucket IPv6 clients for rate limiting.
func WithIPv6Subnet(prefixLen int) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.IPv6Subnet = prefixLen
	}
}

// WithIPAddressHeader sets which header to trust for client IP (e.g. "CF-Connecting-IP").
// Requires TrustedIPs to be set - validated in config.validate().
func WithIPAddressHeader(header string) Option {
	return func(c *config) {
		if c.rateLimit == nil {
			c.rateLimit = ratelimit.DefaultRateLimitConfig()
		}
		c.rateLimit.IPAddressHeader = header
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) {
		c.logger = logger
	}
}

// WithProvider registers an OAuth provider.
// The provider's Name() must be non-empty and unique across all registered providers.
// Nil providers are rejected.
func WithProvider(p port.OAuthProvider) Option {
	return func(c *config) {
		c.providers = append(c.providers, p)
	}
}

// WithAudit configures audit logging. Sinks listed in cfg are registered once
// regardless of how many times this option is applied; appending them here
// instead would duplicate every sink — and so every audit event — on a repeat
// call. New() reads cfg.Sinks and the WithAuditSink list together.
func WithAudit(cfg AuditConfig) Option {
	return func(c *config) {
		c.audit = cfg
	}
}

// WithAuditSink adds a custom audit event sink (e.g. Kafka, NATS, webhook).
// Only takes effect when audit is enabled via WithAudit.
func WithAuditSink(sink audit.EventSink) Option {
	return func(c *config) {
		c.auditSinks = append(c.auditSinks, sink)
	}
}
