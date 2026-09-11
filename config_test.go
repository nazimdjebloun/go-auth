package goauth

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func validTestConfig() Config {
	return Config{
		app: AppConfig{
			Name:        "Test",
			BaseURL:     "http://localhost",
			Environment: EnvironmentDev,
			Database:    DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		},
		session: SessionConfig{
			TTL:             time.Hour,
			IdleTTL:         time.Hour,
			RefreshTokenTTL: time.Hour,
			TokenTTL:        time.Hour,
		},
		cookie:   CookieConfig{Name: "s"},
		security: SecurityConfig{AllowedOrigins: []string{"http://localhost"}},
		secret:   "0123456789abcdef0123456789abcdef",
	}
}

func TestApplyDefaults_Valid(t *testing.T) {
	var cfg Config
	cfg.applyDefaults()
	if cfg.app.Name != "" {
		t.Error("expected empty appName after applyDefaults")
	}
	if cfg.session.TTL != 30*24*time.Hour {
		t.Errorf("expected sessionTTL 30d, got %v", cfg.session.TTL)
	}
	if cfg.session.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("expected refreshTokenTTL 30d, got %v", cfg.session.RefreshTokenTTL)
	}
	if cfg.session.TokenTTL != 1*time.Hour {
		t.Errorf("expected tokenTTL 1h, got %v", cfg.session.TokenTTL)
	}
	if cfg.cookie.Name != "goauth_session" {
		t.Errorf("expected cookie name goauth_session, got %s", cfg.cookie.Name)
	}
	if cfg.cookie.Path != "/" {
		t.Errorf("expected cookie path /, got %s", cfg.cookie.Path)
	}
}

func TestValidate_EmptyDriver(t *testing.T) {
	cfg := validTestConfig()
	cfg.app.Database = DatabaseConfig{}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty driver")
	}
}

func TestValidate_NoDatabase(t *testing.T) {
	cfg := validTestConfig()
	cfg.app.Database = DatabaseConfig{Driver: DriverSQLite}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for no database URL, DB, or Pool")
	}
}

func TestValidate_WithDB(t *testing.T) {
	cfg := validTestConfig()
	cfg.applyDefaults()
	err := cfg.validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_EmptyAppName(t *testing.T) {
	cfg := validTestConfig()
	cfg.app.Name = ""
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty app name")
	}
}

func TestValidate_ZeroSessionTTL(t *testing.T) {
	cfg := validTestConfig()
	cfg.session.TTL = 0
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for zero SessionTTL")
	}
}

func TestValidate_IdleTTLExceedsSessionTTL(t *testing.T) {
	cfg := validTestConfig()
	cfg.session.TTL = 30 * time.Minute
	cfg.session.IdleTTL = time.Hour
	cfg.session.RefreshTokenTTL = 30 * time.Minute
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when IdleTTL > SessionTTL")
	}
}

func TestValidate_RefreshTTLLessThanSessionTTL(t *testing.T) {
	cfg := validTestConfig()
	cfg.session.IdleTTL = 30 * time.Minute
	cfg.session.RefreshTokenTTL = 30 * time.Minute
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when RefreshTTL < SessionTTL")
	}
}

func TestValidate_EmptyAllowedOrigins(t *testing.T) {
	cfg := validTestConfig()
	cfg.security.AllowedOrigins = nil
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty allowed origins")
	}
}

func TestValidate_EmptyCookieName(t *testing.T) {
	cfg := validTestConfig()
	cfg.cookie.Name = ""
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty cookie name")
	}
}

func TestValidate_RequiresEmailWithMailer(t *testing.T) {
	cfg := validTestConfig()
	cfg.mailer = &mockMailer{}
	cfg.registration.EnableEmailPassword = true
	cfg.registration.RequireEmailVerification = true
	cfg.applyDefaults()
	err := cfg.validate()
	if err != nil {
		t.Fatalf("unexpected error when Mailer is set: %v", err)
	}
}

func TestValidate_RequiresEmailMissingMailer(t *testing.T) {
	cfg := validTestConfig()
	cfg.mailer = nil
	cfg.registration.RequireEmailVerification = true
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when RequireEmailVerification is true but Mailer and Email are nil")
	}
}

func TestValidate_WildcardOrigin(t *testing.T) {
	cfg := validTestConfig()
	cfg.security.AllowedOrigins = []string{"*"}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when AllowedOrigins contains *")
	}
}

func TestValidate_EmailConfig(t *testing.T) {
	tests := []struct {
		name    string
		email   EmailConfig
		wantErr string
	}{
		{
			name: "valid starttls",
			email: EmailConfig{
				From: "Auth <auth@example.com>",
				Host: "smtp.example.com",
				Port: 587,
				User: "user",
				Pass: "pass",
				TLS:  TLSStart,
			},
		},
		{
			name: "port too high",
			email: EmailConfig{
				From: "auth@example.com",
				Host: "smtp.example.com",
				Port: 65536,
			},
			wantErr: "email: port must be between 1 and 65535, got 65536",
		},
		{
			name: "port zero",
			email: EmailConfig{
				From: "auth@example.com",
				Host: "smtp.example.com",
				Port: 0,
			},
			wantErr: "email: port must be between 1 and 65535, got 0",
		},
		{
			name: "max port",
			email: EmailConfig{
				From: "auth@example.com",
				Host: "smtp.example.com",
				Port: 65535,
			},
		},
		{
			name: "empty from address",
			email: EmailConfig{
				Host: "smtp.example.com",
				Port: 587,
			},
			wantErr: "email: from address is required",
		},
		{
			name: "invalid from address",
			email: EmailConfig{
				From: "not an email",
				Host: "smtp.example.com",
				Port: 587,
			},
			wantErr: "email: from address \"not an email\" is not valid",
		},
		{
			name: "partial credentials",
			email: EmailConfig{
				From: "auth@example.com",
				Host: "smtp.example.com",
				Port: 587,
				User: "user",
			},
			wantErr: "email: user and pass must both be set or both be empty",
		},
		{
			name: "partial credentials password only",
			email: EmailConfig{
				From: "auth@example.com",
				Host: "smtp.example.com",
				Port: 587,
				Pass: "x",
			},
			wantErr: "email: user and pass must both be set or both be empty",
		},
		{
			name: "unauthenticated smtp",
			email: EmailConfig{
				From: "auth@example.com",
				Host: "smtp.example.com",
				Port: 25,
				TLS:  TLSNone,
			},
		},
		{
			name: "valid tls none",
			email: EmailConfig{
				From: "auth@example.com",
				Host: "smtp.example.com",
				Port: 25,
				TLS:  TLSNone,
			},
		},
		{
			name: "valid tls implicit",
			email: EmailConfig{
				From: "auth@example.com",
				Host: "smtp.example.com",
				Port: 465,
				TLS:  TLSImplicit,
			},
		},
		{
			name: "invalid tls mode",
			email: EmailConfig{
				From: "auth@example.com",
				Host: "smtp.example.com",
				Port: 587,
				TLS:  TLSMode(99),
			},
			wantErr: "email: tls mode must be one of TLSNone, TLSStart, or TLSImplicit, got 99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := append(validConfigOpts(), WithEmail(tt.email))
			_, err := NewConfig(opts...)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNewConfig_WithEmailZeroValueIsValidated(t *testing.T) {
	opts := append(validConfigOpts(), WithEmail(EmailConfig{}))
	_, err := NewConfig(opts...)
	if err == nil {
		t.Fatal("expected zero-value EmailConfig to be validated")
	}
	if !strings.Contains(err.Error(), "email: host is required") {
		t.Fatalf("expected host validation error, got %v", err)
	}
	if !strings.Contains(err.Error(), "email: from address is required") {
		t.Fatalf("expected from validation error, got %v", err)
	}
}

func TestNewConfig_RateLimitValidation(t *testing.T) {
	validEnabledRateLimit := func() ratelimit.Config {
		cfg := *ratelimit.DefaultRateLimitConfig()
		cfg.Enabled = true
		return cfg
	}

	tests := []struct {
		name      string
		rateLimit ratelimit.Config
		wantErr   string
		rejectErr string
	}{
		{
			name: "enabled with invalid default requests",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.Default.Requests = 0
				return cfg
			}(),
			wantErr: "requests must be positive",
		},
		{
			name: "enabled with invalid default window",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.Default.Window = 0
				return cfg
			}(),
			wantErr: "window must be positive",
		},
		{
			name: "enabled with invalid route requests",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.Routes = map[string]ratelimit.Rate{
					"POST /custom": {Requests: -1, Window: time.Minute},
				}
				return cfg
			}(),
			wantErr: "POST /custom",
		},
		{
			name: "enabled with ipv6 subnet too low",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.IPv6Subnet = 0
				return cfg
			}(),
			wantErr: "ipv6_subnet",
		},
		{
			name: "enabled with ipv6 subnet too high",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.IPv6Subnet = 129
				return cfg
			}(),
			wantErr: "ipv6_subnet",
		},
		{
			name: "enabled with valid ipv6 subnet",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.IPv6Subnet = 64
				return cfg
			}(),
			rejectErr: "ipv6_subnet",
		},
		{
			name: "enabled with invalid trusted ip",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.TrustedIPs = []string{"not-an-ip"}
				return cfg
			}(),
			wantErr: "trusted_ips",
		},
		{
			name: "enabled with valid trusted cidr",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.TrustedIPs = []string{"10.0.0.0/8"}
				return cfg
			}(),
			rejectErr: "trusted_ips",
		},
		{
			name: "enabled with valid trusted single ip",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.TrustedIPs = []string{"192.168.1.1"}
				return cfg
			}(),
			rejectErr: "trusted_ips",
		},
		{
			name: "enabled with header and no trusted ips",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.IPAddressHeader = "X-Forwarded-For"
				return cfg
			}(),
			wantErr: "ip_address_header",
		},
		{
			name: "enabled with header and trusted cidr",
			rateLimit: func() ratelimit.Config {
				cfg := validEnabledRateLimit()
				cfg.IPAddressHeader = "X-Forwarded-For"
				cfg.TrustedIPs = []string{"10.0.0.0/8"}
				return cfg
			}(),
			rejectErr: "ip_address_header",
		},
		{
			name: "disabled with otherwise invalid config",
			rateLimit: ratelimit.Config{
				Enabled:    false,
				Default:    ratelimit.Rate{Requests: -1},
				IPv6Subnet: 129,
				TrustedIPs: []string{"not-an-ip"},
			},
		},
		{
			name:      "enabled default config is valid",
			rateLimit: validEnabledRateLimit(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := append(validConfigOpts(), WithRateLimit(tt.rateLimit))
			_, err := NewConfig(opts...)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				if tt.rejectErr != "" && strings.Contains(err.Error(), tt.rejectErr) {
					t.Fatalf("expected no error containing %q, got %v", tt.rejectErr, err)
				}
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestNewConfig_RateLimitStoreIsOptional replaces a case that asserted
// "enabled with a nil Store" was a validation error. It no longer is:
// applyDefaults fills in the in-memory store, which is what makes it safe
// for DefaultRateLimitConfig to leave Store nil — building one there started
// a cleanup goroutine on every WithRateLimit* call that nothing could close.
func TestNewConfig_RateLimitStoreIsOptional(t *testing.T) {
	cfg, err := NewConfig(append(validConfigOpts(), WithRateLimit(ratelimit.Config{
		Enabled:    true,
		Default:    ratelimit.Rate{Requests: 60, Window: time.Minute},
		IPv6Subnet: 64,
	}))...)
	if err != nil {
		t.Fatalf("expected a nil Store to be filled in, got %v", err)
	}
	if cfg.rateLimit.Store == nil {
		t.Fatal("expected applyDefaults to supply the in-memory store")
	}
	if cfg.set.rateLimitStore {
		t.Error("a library-built store must not be marked consumer-owned, or Close() will leak its cleanup goroutine")
	}
}

func TestNewConfig_RateLimitRouteCanBeDisabledWithZeroRequests(t *testing.T) {
	// Rate{Requests: 0} has always meant "don't limit this route" in the
	// middleware and in the docs, but validate rejected it outright, so the
	// documented per-route opt-out was unreachable.
	if _, err := NewConfig(append(validConfigOpts(),
		WithRateLimitRoute("POST /auth/login", ratelimit.Rate{Requests: 0}),
	)...); err != nil {
		t.Fatalf("expected Rate{Requests: 0} to disable a route, got %v", err)
	}
	// The Default has no such reading — a zero there would silently disable
	// limiting on every unlisted route.
	if _, err := NewConfig(append(validConfigOpts(),
		WithRateLimitDefault(ratelimit.Rate{Requests: 0}),
	)...); err == nil {
		t.Error("expected a zero Default to be rejected")
	}
}

func TestNewConfig_RateLimitGranularOptions(t *testing.T) {
	t.Run("enabled preserves default routes", func(t *testing.T) {
		cfg, err := NewConfig(append(validConfigOpts(), WithRateLimitEnabled(true))...)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := cfg.rateLimit.Routes["POST /auth/login"]; !ok {
			t.Fatal("expected default login route to be preserved")
		}
	})

	t.Run("default override preserves routes", func(t *testing.T) {
		opts := append(validConfigOpts(),
			WithRateLimitEnabled(true),
			WithRateLimitDefault(ratelimit.Rate{Requests: 100, Window: time.Minute}),
		)
		cfg, err := NewConfig(opts...)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.rateLimit.Default.Requests != 100 || cfg.rateLimit.Default.Window != time.Minute {
			t.Fatalf("expected default override, got %+v", cfg.rateLimit.Default)
		}
		if _, ok := cfg.rateLimit.Routes["POST /auth/login"]; !ok {
			t.Fatal("expected default login route to be preserved")
		}
	})

	t.Run("route override preserves default routes", func(t *testing.T) {
		customRate := ratelimit.Rate{Requests: 5, Window: time.Minute}
		opts := append(validConfigOpts(),
			WithRateLimitEnabled(true),
			WithRateLimitRoute("POST /custom/endpoint", customRate),
		)
		cfg, err := NewConfig(opts...)
		if err != nil {
			t.Fatal(err)
		}
		if got := cfg.rateLimit.Routes["POST /custom/endpoint"]; got != customRate {
			t.Fatalf("expected custom route %+v, got %+v", customRate, got)
		}
		if _, ok := cfg.rateLimit.Routes["POST /auth/login"]; !ok {
			t.Fatal("expected default login route to be preserved")
		}
	})

	t.Run("store override preserves default and routes", func(t *testing.T) {
		customStore := ratelimit.NewMemoryStore()
		cfg, err := NewConfig(append(validConfigOpts(), WithRateLimitStore(customStore))...)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.rateLimit.Store != customStore {
			t.Fatal("expected custom store to be set")
		}
		if cfg.rateLimit.Default != (ratelimit.Rate{Requests: 60, Window: time.Minute}) {
			t.Fatalf("expected default rate to be preserved, got %+v", cfg.rateLimit.Default)
		}
		if _, ok := cfg.rateLimit.Routes["POST /auth/login"]; !ok {
			t.Fatal("expected default login route to be preserved")
		}
	})

	t.Run("route initializes enabled config by default", func(t *testing.T) {
		customRate := ratelimit.Rate{Requests: 5, Window: time.Minute}
		cfg, err := NewConfig(append(validConfigOpts(), WithRateLimitRoute("POST /custom/endpoint", customRate))...)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.rateLimit == nil {
			t.Fatal("expected rate limit config to be initialized")
		}
		if !cfg.rateLimit.Enabled {
			t.Fatal("expected rate limiting to be enabled by default")
		}
		if got := cfg.rateLimit.Routes["POST /custom/endpoint"]; got != customRate {
			t.Fatalf("expected custom route %+v, got %+v", customRate, got)
		}
	})
}

func validConfigOpts() []Option {
	return []Option{
		func(c *Config) {
			c.app.Name = "Test"
			c.app.BaseURL = "http://localhost"
			c.app.Database.Driver = DriverSQLite
			c.app.Database.URL = "file::memory:?cache=shared"
			c.session.TTL = 30 * 24 * time.Hour
			c.session.IdleTTL = 7 * 24 * time.Hour
			c.session.RefreshTokenTTL = 30 * 24 * time.Hour
			c.session.TokenTTL = 1 * time.Hour
			c.cookie.Name = "goauth_session"
			c.security.AllowedOrigins = []string{"http://localhost"}
			c.registration.EnableInvite = false
			c.secret = "0123456789abcdef0123456789abcdef"
			// EnvironmentDev so applyDefaults auto-fills a log mailer when a
			// test doesn't provide its own WithMailer/WithEmail — the mailer
			// requirement is unconditional now (AdminLogin always needs it).
			c.app.Environment = EnvironmentDev
		},
	}
}

func TestNewConfig_Valid(t *testing.T) {
	cfg, err := NewConfig(validConfigOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.app.Name != "Test" {
		t.Errorf("expected appName Test, got %s", cfg.app.Name)
	}
}

// NewConfig(opts...) is the only supported way to build a config — New()
// must refuse to run against anything else, so a bypassed or hand-built
// config can never reach production with unvalidated (and, for an empty
// secret, cryptographically unsafe) settings.

func TestNewConfig_SetsValidated(t *testing.T) {
	cfg, err := NewConfig(validConfigOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.resolved.validated {
		t.Error("expected NewConfig to set validated = true on success")
	}
}

func TestNewConfig_InvalidReturnsNil(t *testing.T) {
	cfg, err := NewConfig() // no opts — fails validate()
	if err == nil {
		t.Fatal("expected error for empty config")
	}
	// Stronger than "validated is false": a failed NewConfig hands back no
	// Config at all, so there is nothing for a caller who ignored err to
	// pass to New().
	if cfg != nil {
		t.Error("expected NewConfig to return a nil *Config on failure")
	}
}

func TestNew_RejectsZeroValueConfig(t *testing.T) {
	_, err := New(&Config{})
	if err == nil {
		t.Fatal("expected New(&Config{}) to fail — a zero-value config was never validated")
	}
	if !strings.Contains(err.Error(), "NewConfig") {
		t.Errorf("expected error to point at NewConfig, got: %v", err)
	}
}

func TestNew_RejectsNilConfig(t *testing.T) {
	_, err := New(nil)
	if err == nil {
		t.Fatal("expected New(nil) to fail")
	}
	if !strings.Contains(err.Error(), "NewConfig") {
		t.Errorf("expected error to point at NewConfig, got: %v", err)
	}
}

func TestNew_RejectsDefaultConfigWithoutNewConfig(t *testing.T) {
	// A defaulted config — even with fields filled in by hand afterward —
	// must still be rejected, since it never went through validate().
	var cfg Config
	cfg.applyDefaults()
	cfg.app.Name = "Test"
	cfg.app.BaseURL = "http://localhost"
	cfg.app.Database.Driver = DriverSQLite
	cfg.app.Database.DB = &sql.DB{}
	cfg.secret = "0123456789abcdef0123456789abcdef"
	cfg.security.AllowedOrigins = []string{"http://localhost"}

	_, err := New(&cfg)
	if err == nil {
		t.Fatal("expected New() to reject a config built without NewConfig")
	}
}

func TestNewConfig_Invalid(t *testing.T) {
	_, err := NewConfig(func(c *Config) { c.app.Name = "" })
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewConfig_OverridesDefault(t *testing.T) {
	cfg, err := NewConfig(
		func(c *Config) {
			c.app.Name = "Custom"
			c.app.BaseURL = "http://localhost"
			c.app.Environment = EnvironmentDev
			c.app.Database.Driver = DriverSQLite
			c.app.Database.URL = "file::memory:?cache=shared"
			c.session.TTL = 7 * 24 * time.Hour
			c.session.IdleTTL = 7 * 24 * time.Hour
			c.session.RefreshTokenTTL = 7 * 24 * time.Hour
			c.session.TokenTTL = 1 * time.Hour
			c.cookie.Name = "goauth_session"
			c.security.AllowedOrigins = []string{"http://localhost"}
			c.registration.EnableInvite = false
			c.secret = "0123456789abcdef0123456789abcdef"
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.session.TTL != 7*24*time.Hour {
		t.Errorf("expected sessionTTL 7d, got %v", cfg.session.TTL)
	}
}

func TestNewConfig_SameSiteDefault(t *testing.T) {
	cfg, err := NewConfig(validConfigOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSiteLaxMode, got %v", cfg.cookie.SameSite)
	}
}

func TestWithCookie_PartialConfigKeepsDefaults(t *testing.T) {
	cfg, err := NewConfig(append(validConfigOpts(),
		WithCookie(CookieConfig{Name: "custom_session"}),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.cookie.Name != "custom_session" {
		t.Errorf("expected cookie name custom_session, got %q", cfg.cookie.Name)
	}
	if cfg.cookie.Path != "/" {
		t.Errorf("expected default cookie path /, got %q", cfg.cookie.Path)
	}
	if cfg.cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected default SameSiteLaxMode, got %v", cfg.cookie.SameSite)
	}
}

func TestWithCookie_ExplicitOverridesDefaults(t *testing.T) {
	cfg, err := NewConfig(append(validConfigOpts(),
		// Secure accompanies SameSite=None because browsers reject the pair
		// without it, and config.validate() now says so rather than letting
		// it fail silently in a browser.
		WithCookie(CookieConfig{Name: "custom", Domain: "example.com", Path: "/api", SameSite: http.SameSiteNoneMode, Secure: SecureAlways()}),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.cookie.Name != "custom" {
		t.Errorf("expected cookie name custom, got %q", cfg.cookie.Name)
	}
	if cfg.cookie.Domain != "example.com" {
		t.Errorf("expected cookie domain example.com, got %q", cfg.cookie.Domain)
	}
	if cfg.cookie.Path != "/api" {
		t.Errorf("expected cookie path /api, got %q", cfg.cookie.Path)
	}
	if cfg.cookie.SameSite != http.SameSiteNoneMode {
		t.Errorf("expected SameSiteNoneMode, got %v", cfg.cookie.SameSite)
	}
}

func TestValidate_SecretRequired(t *testing.T) {
	cfg := validTestConfig()
	cfg.secret = ""
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
	if !strings.Contains(err.Error(), "secret: signing secret is required") {
		t.Fatalf("expected secret required error, got %v", err)
	}
}

func TestValidate_SecretTooShort(t *testing.T) {
	cfg := validTestConfig()
	cfg.secret = "0123456789abcdef0123456789abcde"
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for 31-byte secret")
	}
	if !strings.Contains(err.Error(), "secret: signing secret must be at least 32 bytes") {
		t.Fatalf("expected secret too short error, got %v", err)
	}
}

func TestValidate_Secret32BytesOK(t *testing.T) {
	cfg := validTestConfig()
	cfg.applyDefaults()
	err := cfg.validate()
	if err != nil {
		t.Fatalf("unexpected error for 32-byte secret: %v", err)
	}
}

func TestWithSecret_SetsSecret(t *testing.T) {
	var cfg Config
	WithSecret("0123456789abcdef0123456789abcdef")(&cfg)
	if cfg.secret != "0123456789abcdef0123456789abcdef" {
		t.Fatal("expected secret to be set")
	}
}

func TestWithPepperRotatedAt_SetsTimestamp(t *testing.T) {
	var cfg Config
	rotatedAt := time.Date(2026, 9, 11, 18, 0, 0, 0, time.UTC)
	WithPepperRotatedAt(rotatedAt)(&cfg)
	if !cfg.security.PepperRotatedAt.Equal(rotatedAt) {
		t.Fatalf("expected PepperRotatedAt %v, got %v", rotatedAt, cfg.security.PepperRotatedAt)
	}
}

func TestWithPepperRotatedAt_DefaultIsZero(t *testing.T) {
	// Never configured: the fixed-epoch zero default keeps the stale-pepper
	// branch dormant rather than stamping boot time (which would disagree
	// across instances behind a load balancer).
	var cfg Config
	if !cfg.security.PepperRotatedAt.IsZero() {
		t.Fatalf("expected zero PepperRotatedAt by default, got %v", cfg.security.PepperRotatedAt)
	}
}

func TestWithPepperRotatedAt_SurvivesClone(t *testing.T) {
	// Rotation metadata must reach New() identically for every Auth built
	// from one Config — clone() must not drop it.
	cfg := validTestConfig()
	rotatedAt := time.Date(2026, 9, 11, 18, 0, 0, 0, time.UTC)
	WithPepperRotatedAt(rotatedAt)(&cfg)
	cloned := cfg.clone()
	if !cloned.security.PepperRotatedAt.Equal(rotatedAt) {
		t.Fatalf("expected cloned PepperRotatedAt %v, got %v", rotatedAt, cloned.security.PepperRotatedAt)
	}
}

type mockMailer struct{}

func (m *mockMailer) Send(_ context.Context, _, _, _, _ string) error { return nil }

// SameSite=None without Secure is rejected by every current browser, so the
// pairing yields no session at all rather than a weaker one. Catch it in
// config instead of leaving it to look like "login succeeds but never sticks".
func TestValidate_SameSiteNoneRequiresSecure(t *testing.T) {
	cfg := validTestConfig()
	cfg.cookie = CookieConfig{Name: "s", SameSite: http.SameSiteNoneMode}
	cfg.applyDefaults()
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected an error for SameSite=None without Secure")
	}
	if !strings.Contains(err.Error(), "same_site=None requires a secure cookie") {
		t.Errorf("unexpected error: %v", err)
	}
}

// The pairing the cross-site deployment actually needs.
func TestValidate_SameSiteNoneWithSecureIsAccepted(t *testing.T) {
	cfg := validTestConfig()
	cfg.cookie = CookieConfig{Name: "s", SameSite: http.SameSiteNoneMode, Secure: SecureAlways()}
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		t.Fatalf("SameSite=None with Secure must be accepted, got: %v", err)
	}
}
