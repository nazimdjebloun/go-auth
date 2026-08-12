package goauth

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/schema"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	_ "modernc.org/sqlite"
)

// Regression tests for the config-defaults audit. Every case here failed
// before defaults moved from a pre-seeded defaultConfig() into applyDefaults():
// options that assign a struct wholesale cannot tell a zero field from an
// omitted one, so any partially-filled option silently wiped the defaults for
// the fields the consumer left alone.

type recordingSink struct{}

func (recordingSink) Handle(_ context.Context, _ audit.Event) error        { return nil }
func (recordingSink) HandleBatch(_ context.Context, _ []audit.Event) error { return nil }

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
		WithMailer(noopMailer{}),
	}
	return append(base, extra...)
}

// buildAuth runs the full New() path (which is where CSRF wiring happens) on an
// in-memory SQLite database.
func buildAuth(t *testing.T, opts ...Option) *Auth {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	schemaSQL, err := GetSchema("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schema.SplitSQL(schemaSQL) {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	cfg, err := NewConfig(append(opts, WithApp(AppConfig{
		Name:     "app",
		BaseURL:  "https://example.com",
		Database: DatabaseConfig{Driver: DriverSQLite, DB: db},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
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
				WithMailer(noopMailer{}),
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
		{"explicit true outside dev", EnvironmentProd, AllowPlaintextEmailLinks(), true},
		{"explicit false inside dev", EnvironmentDev, RequireHTTPSEmailLinks(), false},
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
				WithMailer(noopMailer{}),
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

func TestDefaults_NoMailerOK_WhenNoEmailFeatureNeedsOne(t *testing.T) {
	_, err := NewConfig(
		WithApp(AppConfig{
			Name:        "app",
			BaseURL:     "https://example.com",
			Environment: EnvironmentProd,
			Database:    DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		}),
		WithSecret("0123456789abcdef0123456789abcdef"),
		WithSecurity(SecurityConfig{
			AllowedOrigins:        []string{"https://example.com"},
			DisableAdminTwoFactor: true,
		}),
		// No WithMailer/WithEmail, no RequireEmailVerification/EnableInvite/
		// RequireEmail2FA/DefaultTwoFactorEnabled — an API-only deployment.
	)
	if err != nil {
		t.Fatalf("expected no mailer to be valid with every email feature off, got: %v", err)
	}
}

func TestDefaults_NoMailerFails_WhenAdminTwoFactorStillOn(t *testing.T) {
	_, err := NewConfig(
		WithApp(AppConfig{
			Name:        "app",
			BaseURL:     "https://example.com",
			Environment: EnvironmentProd,
			Database:    DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		}),
		WithSecret("0123456789abcdef0123456789abcdef"),
		WithSecurity(SecurityConfig{AllowedOrigins: []string{"https://example.com"}}),
		// DisableAdminTwoFactor left at its secure zero value (false).
	)
	if err == nil {
		t.Fatal("expected an error: AdminLogin's two-factor challenge still needs a mailer")
	}
	if !strings.Contains(err.Error(), "AdminLogin two-factor") {
		t.Errorf("error = %v, want it to name AdminLogin two-factor as the reason", err)
	}
}

func TestDefaults_NoMailerFails_WhenEnableInviteOn(t *testing.T) {
	_, err := NewConfig(
		WithApp(AppConfig{
			Name:        "app",
			BaseURL:     "https://example.com",
			Environment: EnvironmentProd,
			Database:    DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		}),
		WithSecret("0123456789abcdef0123456789abcdef"),
		WithSecurity(SecurityConfig{
			AllowedOrigins:        []string{"https://example.com"},
			DisableAdminTwoFactor: true,
		}),
		WithRegistration(RegistrationConfig{EnableEmailPassword: true, EnableInvite: true}),
	)
	if err == nil {
		t.Fatal("expected an error: EnableInvite needs a mailer even with AdminLogin two-factor disabled")
	}
	if !strings.Contains(err.Error(), "EnableInvite") {
		t.Errorf("error = %v, want it to name EnableInvite as the reason", err)
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
	// The path values are arbitrary markers — nothing is routed here. The test
	// writes through the library's copy and checks the caller's slice is
	// unaffected, which it was not before DisabledPaths was cloned.
	shared := *ratelimit.DefaultRateLimitConfig()
	shared.DisabledPaths = []string{"/caller-owned"}

	cfg, err := NewConfig(minimalOpts(WithRateLimit(shared))...)
	if err != nil {
		t.Fatal(err)
	}
	cfg.rateLimit.DisabledPaths[0] = "/written-by-library"
	if shared.DisabledPaths[0] != "/caller-owned" {
		t.Errorf("caller's DisabledPaths slice was aliased: %v", shared.DisabledPaths)
	}
}

func TestWithAudit_DoesNotDuplicateSinksOnRepeat(t *testing.T) {
	var cfg config
	sink := recordingSink{}
	opt := WithAudit(AuditConfig{Enabled: true, Sinks: []audit.EventSink{sink}})
	opt(&cfg)
	opt(&cfg)
	if len(cfg.auditSinks) != 0 {
		t.Errorf("WithAudit must not accumulate into auditSinks, got %d", len(cfg.auditSinks))
	}
	if len(cfg.audit.Sinks) != 1 {
		t.Errorf("audit.Sinks = %d, want 1 after a repeated option", len(cfg.audit.Sinks))
	}
}

func TestCSRFToken_OnByDefault(t *testing.T) {
	// The layer is on unless explicitly disabled: a nil CSRFToken means
	// "build one with defaults", not "off".
	a := buildAuth(t, minimalOpts()...)
	defer a.Close()
	if a.cfg.csrfToken == nil {
		t.Fatal("double-submit token layer must be on by default")
	}
	if a.cfg.csrfToken.CookieName != "_csrf" || a.cfg.csrfToken.HeaderName != "X-CSRF-Token" {
		t.Errorf("unexpected auto-created config: %+v", a.cfg.csrfToken)
	}
	if len(a.cfg.csrfToken.Secret) == 0 {
		t.Error("signing secret was not derived into the token config")
	}
}

func TestCSRFToken_Disable(t *testing.T) {
	a := buildAuth(t, minimalOpts(WithSecurity(SecurityConfig{
		AllowedOrigins:   []string{"https://example.com"},
		DisableCSRFToken: true,
	}))...)
	defer a.Close()
	if a.cfg.csrfToken != nil {
		t.Fatal("DisableCSRFToken must leave csrfToken nil so the middleware passes through")
	}
}

func TestCSRFToken_DisableWithMissingHeadersIsRejected(t *testing.T) {
	// Each is a defensible trade on its own; together they remove every CSRF
	// defense, so the combination is a configuration error.
	_, err := NewConfig(minimalOpts(WithSecurity(SecurityConfig{
		AllowedOrigins:          []string{"https://example.com"},
		DisableCSRFToken:        true,
		AllowMissingCSRFHeaders: true,
	}))...)
	if err == nil {
		t.Fatal("expected the combination to be rejected")
	}
	if !strings.Contains(err.Error(), "DisableCSRFToken and AllowMissingCSRFHeaders") {
		t.Errorf("error should name both fields, got: %v", err)
	}
}
