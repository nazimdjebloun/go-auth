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

func TestDefaultConfig_Valid(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.appName != "" {
		t.Error("expected empty appName in DefaultConfig")
	}
	if cfg.sessionTTL != 30*24*time.Hour {
		t.Errorf("expected sessionTTL 30d, got %v", cfg.sessionTTL)
	}
	if cfg.refreshTokenTTL != 30*24*time.Hour {
		t.Errorf("expected refreshTokenTTL 30d, got %v", cfg.refreshTokenTTL)
	}
	if cfg.tokenTTL != 1*time.Hour {
		t.Errorf("expected tokenTTL 1h, got %v", cfg.tokenTTL)
	}
	if cfg.cookie.Name != "goauth_session" {
		t.Errorf("expected cookie name goauth_session, got %s", cfg.cookie.Name)
	}
	if cfg.cookie.Path != "/" {
		t.Errorf("expected cookie path /, got %s", cfg.cookie.Path)
	}
}

func TestValidate_EmptyDriver(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"http://localhost"}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty driver")
	}
}

func TestValidate_NoDatabase(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"http://localhost"}, database: DatabaseConfig{Driver: DriverSQLite}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for no database URL, DB, or Pool")
	}
}

func TestValidate_WithDB(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"http://localhost"}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_EmptyAppName(t *testing.T) {
	cfg := Config{baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"http://localhost"}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty app name")
	}
}

func TestValidate_ZeroSessionTTL(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"http://localhost"}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for zero SessionTTL")
	}
}

func TestValidate_IdleTTLExceedsSessionTTL(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: 30 * time.Minute, sessionIdleTTL: time.Hour, refreshTokenTTL: 30 * time.Minute, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"http://localhost"}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when IdleTTL > SessionTTL")
	}
}

func TestValidate_RefreshTTLLessThanSessionTTL(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: 30 * time.Minute, refreshTokenTTL: 30 * time.Minute, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"http://localhost"}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when RefreshTTL < SessionTTL")
	}
}

func TestValidate_EmptyAllowedOrigins(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty allowed origins")
	}
}

func TestValidate_EmptyCookieName(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, allowedOrigins: []string{"http://localhost"}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty cookie name")
	}
}

func TestValidate_RequiresEmailWithMailer(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"http://localhost"}, mailer: &mockMailer{}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	cfg.registration.EnableEmailPassword = true
	cfg.registration.RequireEmailVerification = true
	err := cfg.validate()
	if err != nil {
		t.Fatalf("unexpected error when Mailer is set: %v", err)
	}
}

func TestValidate_RequiresEmailMissingMailer(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"http://localhost"}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	cfg.registration.RequireEmailVerification = true
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when RequireEmailVerification is true but Mailer and Email are nil")
	}
}

func TestValidate_WildcardOrigin(t *testing.T) {
	cfg := Config{appName: "Test", baseURL: "http://localhost", sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour, tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"}, allowedOrigins: []string{"*"}, database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
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
				From:    "Auth <auth@example.com>",
				Host:    "smtp.example.com",
				Port:    587,
				User:    "user",
				Pass:    "pass",
				TLSMode: TLSStart,
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
				From:    "auth@example.com",
				Host:    "smtp.example.com",
				Port:    25,
				TLSMode: TLSNone,
			},
		},
		{
			name: "valid tls none",
			email: EmailConfig{
				From:    "auth@example.com",
				Host:    "smtp.example.com",
				Port:    25,
				TLSMode: TLSNone,
			},
		},
		{
			name: "valid tls implicit",
			email: EmailConfig{
				From:    "auth@example.com",
				Host:    "smtp.example.com",
				Port:    465,
				TLSMode: TLSImplicit,
			},
		},
		{
			name: "invalid tls mode",
			email: EmailConfig{
				From:    "auth@example.com",
				Host:    "smtp.example.com",
				Port:    587,
				TLSMode: TLSMode(99),
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
			name:      "enabled with nil store",
			rateLimit: ratelimit.Config{Enabled: true},
			wantErr:   "store is nil",
		},
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

	t.Run("route only initializes disabled config", func(t *testing.T) {
		customRate := ratelimit.Rate{Requests: 5, Window: time.Minute}
		cfg, err := NewConfig(append(validConfigOpts(), WithRateLimitRoute("POST /custom/endpoint", customRate))...)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.rateLimit == nil {
			t.Fatal("expected rate limit config to be initialized")
		}
		if cfg.rateLimit.Enabled {
			t.Fatal("expected rate limiting to remain disabled")
		}
		if got := cfg.rateLimit.Routes["POST /custom/endpoint"]; got != customRate {
			t.Fatalf("expected custom route %+v, got %+v", customRate, got)
		}
	})
}

func validConfigOpts() []func(*Config) {
	return []func(*Config){
		func(c *Config) {
			c.appName = "Test"
			c.baseURL = "http://localhost"
			c.database.Driver = DriverSQLite
			c.database.URL = "file::memory:?cache=shared"
			c.sessionTTL = 30 * 24 * time.Hour
			c.sessionIdleTTL = 7 * 24 * time.Hour
			c.refreshTokenTTL = 30 * 24 * time.Hour
			c.tokenTTL = 1 * time.Hour
			c.cookie.Name = "goauth_session"
			c.allowedOrigins = []string{"http://localhost"}
			c.registration.EnableInvite = false
		},
	}
}

func TestNewConfig_Valid(t *testing.T) {
	cfg, err := NewConfig(validConfigOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.appName != "Test" {
		t.Errorf("expected appName Test, got %s", cfg.appName)
	}
}

func TestNewConfig_Invalid(t *testing.T) {
	_, err := NewConfig(func(c *Config) { c.appName = "" })
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewConfig_OverridesDefault(t *testing.T) {
	cfg, err := NewConfig(
		func(c *Config) {
			c.appName = "Custom"
			c.baseURL = "http://localhost"
			c.database.Driver = DriverSQLite
			c.database.URL = "file::memory:?cache=shared"
			c.sessionTTL = 7 * 24 * time.Hour
			c.sessionIdleTTL = 7 * 24 * time.Hour
			c.refreshTokenTTL = 7 * 24 * time.Hour
			c.tokenTTL = 1 * time.Hour
			c.cookie.Name = "goauth_session"
			c.allowedOrigins = []string{"http://localhost"}
			c.registration.EnableInvite = false
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.sessionTTL != 7*24*time.Hour {
		t.Errorf("expected sessionTTL 7d, got %v", cfg.sessionTTL)
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

type mockMailer struct{}

func (m *mockMailer) Send(_ context.Context, _, _, _, _ string) error { return nil }
