package goauth

import (
	"fmt"
	"net"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

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
		// zero Store here means New will build one, and that one
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
func (c *Config) validateRateLimit() []error {
	var errs []error
	if c.rateLimit == nil || !c.rateLimit.Enabled {
		return nil
	}
	rl := c.rateLimit
	// A nil Store requests a per-Auth in-memory store. New creates it only
	// after all fallible startup work succeeds.
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

func (c *Config) applyRateLimitDefaults() {
	if c.rateLimit == nil {
		c.rateLimit = ratelimit.DefaultRateLimitConfig()
	}
}
