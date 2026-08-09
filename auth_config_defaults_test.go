package goauth

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

// Regression tests for the config-defaults audit. Every case here failed
// before defaults moved from a pre-seeded defaultConfig() into applyDefaults():
// options that assign a struct wholesale cannot tell a zero field from an
// omitted one, so any partially-filled option silently wiped the defaults for
// the fields the consumer left alone.

type noopMailer struct{}

func (noopMailer) Send(_ context.Context, _, _, _, _ string) error { return nil }

// minimalOpts is the smallest configuration that should produce a working
// library — anything it does not mention must come back defaulted.
func minimalOpts(extra ...Option) []Option {
	base := []Option{
		WithApp(AppConfig{
			Name:     "app",
			BaseURL:  "https://example.com",
			Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		}),
		WithSecret("0123456789abcdef0123456789abcdef"),
		WithSecurity(SecurityConfig{AllowedOrigins: []string{"https://example.com"}}),
	}
	return append(base, extra...)
}

func TestDefaults_MinimalConfigIsValid(t *testing.T) {
	// Invites defaulted to on while also requiring a mailer, so the smallest
	// possible configuration used to be rejected outright.
	if _, err := NewConfig(minimalOpts()...); err != nil {
		t.Fatalf("minimal config must be valid, got: %v", err)
	}
}

func TestDefaults_SecurityKeepsPasswordPolicy(t *testing.T) {
	cfg, err := NewConfig(minimalOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	want := domain.PasswordPolicy{MinLength: 8, RequireDigit: true}
	if cfg.passwordPolicy != want {
		t.Errorf("password policy = %+v, want %+v", cfg.passwordPolicy, want)
	}
	if cfg.tokenTTL != time.Hour {
		t.Errorf("tokenTTL = %v, want 1h", cfg.tokenTTL)
	}
}

func TestDefaults_SecurityHonoursExplicitPasswordPolicy(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithSecurity(SecurityConfig{
		AllowedOrigins: []string{"https://example.com"},
		PasswordPolicy: domain.PasswordPolicy{MinLength: 16},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.passwordPolicy.MinLength != 16 || cfg.passwordPolicy.RequireDigit {
		t.Errorf("explicit policy was not preserved: %+v", cfg.passwordPolicy)
	}
}

func TestDefaults_AppKeepsEnvironment(t *testing.T) {
	cfg, err := NewConfig(minimalOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.environment != EnvironmentProd {
		t.Errorf("environment = %q, want %q", cfg.environment, EnvironmentProd)
	}
}

func TestDefaults_PartialSessionKeepsGraceAndDebounce(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithSession(SessionConfig{
		TTL:             24 * time.Hour,
		IdleTTL:         time.Hour,
		RefreshTokenTTL: 48 * time.Hour,
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.graceWindow != 5*time.Second {
		t.Errorf("graceWindow = %v, want 5s", cfg.graceWindow)
	}
	if cfg.touchDebounce != 5*time.Minute {
		t.Errorf("touchDebounce = %v, want 5m", cfg.touchDebounce)
	}
}

func TestDefaults_SessionDisabledSentinel(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithSession(SessionConfig{
		GraceWindow:   Disabled,
		TouchDebounce: Disabled,
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.graceWindow != 0 || cfg.touchDebounce != 0 {
		t.Errorf("Disabled must turn the feature off, got grace=%v debounce=%v",
			cfg.graceWindow, cfg.touchDebounce)
	}
}

func TestDefaults_PartialRegistrationKeepsTTLs(t *testing.T) {
	// Zero TTLs meant invites and verification codes expired the instant they
	// were created, with no error anywhere.
	cfg, err := NewConfig(minimalOpts(
		WithMailer(noopMailer{}),
		WithRegistration(RegistrationConfig{
			EnableEmailPassword: true,
			EnableInvite:        true,
			AllowPublic:         true,
		}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.registration.InviteTTL != 7*24*time.Hour {
		t.Errorf("InviteTTL = %v, want 168h", cfg.registration.InviteTTL)
	}
	if cfg.registration.VerificationCodeTTL != 15*time.Minute {
		t.Errorf("VerificationCodeTTL = %v, want 15m", cfg.registration.VerificationCodeTTL)
	}
	if cfg.registration.EnableOAuth {
		t.Error("explicit registration flags must not be merged with defaults")
	}
}

func TestDefaults_OrganizationsInviteTTL(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithOrganizations(OrganizationConfig{Enable: true}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.organizations.InviteTTL != 7*24*time.Hour {
		t.Errorf("org InviteTTL = %v, want 168h", cfg.organizations.InviteTTL)
	}
}

func TestDefaults_CookieNamesAndPath(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithCookie(CookieConfig{Name: "app_session"}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.cookie.Name != "app_session" {
		t.Errorf("cookie name = %q", cfg.cookie.Name)
	}
	if cfg.cookie.RefreshName != "goauth_refresh" {
		t.Errorf("refresh cookie name = %q, want goauth_refresh", cfg.cookie.RefreshName)
	}
	if cfg.cookie.Path != "/" {
		t.Errorf("cookie path = %q, want /", cfg.cookie.Path)
	}
}

func TestCookieSecure_Resolution(t *testing.T) {
	tests := []struct {
		name string
		env  Environment
		url  string
		set  *bool
		want bool
	}{
		{"prod https derives secure", EnvironmentProd, "https://example.com", nil, true},
		{"prod http still secure", EnvironmentProd, "http://example.com", nil, true},
		{"dev http derives insecure", EnvironmentDev, "http://localhost:8080", nil, false},
		{"dev https derives secure", EnvironmentDev, "https://localhost:8080", nil, true},
		{"explicit never is honoured", EnvironmentProd, "https://example.com", SecureNever(), false},
		{"explicit always is honoured", EnvironmentDev, "http://localhost", SecureAlways(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewConfig(
				WithApp(AppConfig{
					Name:        "app",
					BaseURL:     tt.url,
					Environment: tt.env,
					Database:    DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
				}),
				WithSecret("0123456789abcdef0123456789abcdef"),
				WithSecurity(SecurityConfig{AllowedOrigins: []string{tt.url}}),
				WithCookie(CookieConfig{Secure: tt.set}),
			)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.cookieSecure != tt.want {
				t.Errorf("cookieSecure = %v, want %v", cfg.cookieSecure, tt.want)
			}
		})
	}
}

func TestDefaults_NegativeDurationIsAnErrorNotDisabled(t *testing.T) {
	// Only the exact Disabled sentinel means "off" — a stray negative must be
	// rejected rather than silently normalized to 0.
	_, err := NewConfig(minimalOpts(WithSession(SessionConfig{
		GraceWindow: -5 * time.Second,
	}))...)
	if err == nil {
		t.Fatal("expected error for a negative grace window that is not Disabled")
	}
	if !strings.Contains(err.Error(), "grace_window") {
		t.Errorf("error should name the field, got: %v", err)
	}
}

func TestValidate_RejectsNegativeSessionDurations(t *testing.T) {
	// Disabled normalizes to 0 in applyDefaults; a hand-built config with a
	// negative value must still be rejected by validate.
	cfg := config{
		appName: "Test", baseURL: "https://example.com", environment: EnvironmentProd,
		sessionTTL: time.Hour, sessionIdleTTL: time.Hour, refreshTokenTTL: time.Hour,
		tokenTTL: time.Hour, cookie: CookieConfig{Name: "s"},
		allowedOrigins: []string{"https://example.com"},
		database:       DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		secret:         "0123456789abcdef0123456789abcdef",
		registration:   RegistrationConfig{InviteTTL: time.Hour, VerificationCodeTTL: time.Hour},
		maxLifetime:    -time.Hour,
	}
	if err := cfg.validate(); err == nil {
		t.Fatal("expected error for negative max_lifetime")
	}
}

func TestValidate_MaxLifetimeBelowSessionTTL(t *testing.T) {
	_, err := NewConfig(minimalOpts(WithSession(SessionConfig{
		TTL:             24 * time.Hour,
		IdleTTL:         time.Hour,
		RefreshTokenTTL: 48 * time.Hour,
		MaxLifetime:     time.Hour,
	}))...)
	if err == nil {
		t.Fatal("expected error when max_lifetime < session_ttl")
	}
}

func TestAllowHTTPURLs_Resolution(t *testing.T) {
	tests := []struct {
		name string
		env  Environment
		set  *bool
		want bool
	}{
		{"dev derives allow", EnvironmentDev, nil, true},
		{"prod derives refuse", EnvironmentProd, nil, false},
		{"staging derives refuse", EnvironmentStaging, nil, false},
		{"explicit true outside dev", EnvironmentProd, Bool(true), true},
		{"explicit false inside dev", EnvironmentDev, Bool(false), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewConfig(
				WithApp(AppConfig{
					Name:        "app",
					BaseURL:     "https://example.com",
					Environment: tt.env,
					Database:    DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
				}),
				WithSecret("0123456789abcdef0123456789abcdef"),
				WithSecurity(SecurityConfig{
					AllowedOrigins: []string{"https://example.com"},
					AllowHTTPURLs:  tt.set,
				}),
			)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.allowHTTPURLs != tt.want {
				t.Errorf("allowHTTPURLs = %v, want %v", cfg.allowHTTPURLs, tt.want)
			}
		})
	}
}

func TestDefaults_DevImpliesAllowHTTPURLs(t *testing.T) {
	cfg, err := NewConfig(
		WithApp(AppConfig{
			Name:        "app",
			BaseURL:     "http://localhost:8080",
			Environment: EnvironmentDev,
			Database:    DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		}),
		WithSecret("0123456789abcdef0123456789abcdef"),
		WithSecurity(SecurityConfig{AllowedOrigins: []string{"http://localhost:8080"}}),
		WithMailer(noopMailer{}), // custom mailer, no EmailConfig anywhere
	)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.allowHTTPURLs {
		t.Error("dev environment must permit http:// links regardless of transport")
	}
}

func TestWithRateLimit_DeepCopiesRoutes(t *testing.T) {
	// A value parameter copies the map header, not the map: without an explicit
	// clone, WithRateLimitRoute wrote through to the consumer's own map.
	shared := *ratelimit.DefaultRateLimitConfig()
	shared.TrustedIPs = []string{"10.0.0.1"}
	before := shared.Routes["POST /auth/login"]

	if _, err := NewConfig(minimalOpts(
		WithRateLimit(shared),
		WithRateLimitRoute("POST /auth/login", ratelimit.Rate{Requests: 999, Window: time.Minute}),
		WithTrustedIPs([]string{"10.0.0.2"}),
	)...); err != nil {
		t.Fatal(err)
	}

	if got := shared.Routes["POST /auth/login"]; got != before {
		t.Errorf("caller's Routes map was mutated: %+v (was %+v)", got, before)
	}
	if shared.TrustedIPs[0] != "10.0.0.1" {
		t.Errorf("caller's TrustedIPs slice was mutated: %v", shared.TrustedIPs)
	}
}

func TestWithRateLimit_DeepCopiesDisabledPaths(t *testing.T) {
	shared := *ratelimit.DefaultRateLimitConfig()
	shared.DisabledPaths = []string{"/health"}

	cfg, err := NewConfig(minimalOpts(WithRateLimit(shared))...)
	if err != nil {
		t.Fatal(err)
	}
	cfg.rateLimit.DisabledPaths[0] = "/mutated"
	if shared.DisabledPaths[0] != "/health" {
		t.Errorf("caller's DisabledPaths slice was aliased: %v", shared.DisabledPaths)
	}
}
