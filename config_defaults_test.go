package goauth

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
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
		WithSecret("0123456789abcdef0123456789abcdef"), WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://example.com"}}), WithMailer(noopMailer{}),
	}
	return append(base, extra...)
}

// buildAuth runs the full New() path (which is where CSRF wiring happens) on an
// in-memory SQLite database.
func buildAuth(t *testing.T, opts ...Option) *Auth {
	t.Helper()
	// Most HTTP fixtures exercise an explicitly public password application.
	opts = append([]Option{WithRegistration(RegistrationConfig{AllowPublic: true, EmailPassword: true})}, opts...)
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	// Private in-memory databases exist per connection, so keep the schema's
	// connection for requests and background workers alike.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() { _ = db.Close() })
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
	if cfg.security.PasswordPolicy != want {
		t.Errorf("password policy = %+v, want %+v", cfg.security.PasswordPolicy, want)
	}
	if cfg.session.TokenTTL != time.Hour {
		t.Errorf("tokenTTL = %v, want 1h", cfg.session.TokenTTL)
	}
}

func TestDefaults_SecurityHonoursExplicitPasswordPolicy(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://example.com"}}), WithSecurity(SecurityConfig{

		PasswordPolicy: domain.PasswordPolicy{MinLength: 16},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.security.PasswordPolicy.MinLength != 16 || cfg.security.PasswordPolicy.RequireDigit {
		t.Errorf("explicit policy was not preserved: %+v", cfg.security.PasswordPolicy)
	}
}

func TestDefaults_AppKeepsEnvironment(t *testing.T) {
	cfg, err := NewConfig(minimalOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.app.Environment != EnvironmentProd {
		t.Errorf("environment = %q, want %q", cfg.app.Environment, EnvironmentProd)
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
	if cfg.resolved.graceWindow != 5*time.Second {
		t.Errorf("graceWindow = %v, want 5s", cfg.resolved.graceWindow)
	}
	if cfg.resolved.touchDebounce != 5*time.Minute {
		t.Errorf("touchDebounce = %v, want 5m", cfg.resolved.touchDebounce)
	}
}

func TestDefaults_SessionExplicitZeroMeansOff(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithSession(SessionConfig{
		GraceWindow:   Duration(0),
		TouchDebounce: Duration(0),
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.resolved.graceWindow != 0 || cfg.resolved.touchDebounce != 0 {
		t.Errorf("Duration(0) must turn the feature off, got grace=%v debounce=%v",
			cfg.resolved.graceWindow, cfg.resolved.touchDebounce)
	}
}

// TestDefaults_SessionNilLeavesDefault guards the exact bug that motivated
// switching GraceWindow/TouchDebounce to *time.Duration: with a plain
// time.Duration field, a struct literal that simply doesn't mention the
// field is indistinguishable from one that sets it to 0, so "leave it
// unset" and "turn it off" collided. A *time.Duration field makes "unset"
// (nil) and "off" (a pointer to 0) two different values.
func TestDefaults_SessionNilLeavesDefault(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithSession(SessionConfig{
		TTL:             24 * time.Hour,
		IdleTTL:         time.Hour,
		RefreshTokenTTL: 48 * time.Hour,
		// GraceWindow/TouchDebounce deliberately omitted — nil, not 0.
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.resolved.graceWindow != 5*time.Second {
		t.Errorf("graceWindow = %v, want the 5s default (nil must not mean off)", cfg.resolved.graceWindow)
	}
	if cfg.resolved.touchDebounce != 5*time.Minute {
		t.Errorf("touchDebounce = %v, want the 5m default (nil must not mean off)", cfg.resolved.touchDebounce)
	}
}

func TestDefaults_PartialRegistrationKeepsTTLs(t *testing.T) {
	// Zero TTLs meant invites and verification codes expired the instant they
	// were created, with no error anywhere.
	cfg, err := NewConfig(minimalOpts(
		WithMailer(noopMailer{}),
		WithRegistration(RegistrationConfig{
			EmailPassword: true,
			InviteSignup:  true,
			AllowPublic:   true,
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
	if cfg.registration.VerificationResendInterval != 60*time.Second {
		t.Errorf("VerificationResendInterval = %v, want 60s", cfg.registration.VerificationResendInterval)
	}
	if cfg.registration.OAuth {
		t.Error("explicit registration flags must not be merged with defaults")
	}
}

func TestDefaults_VerificationResendInterval(t *testing.T) {
	// Unset means the secure default (60s throttle), not disabled. Explicit
	// values survive; negative opts back out to no minimum.
	var unset Config
	unset.applyDefaults()
	if unset.registration.VerificationResendInterval != 60*time.Second {
		t.Errorf("default VerificationResendInterval = %v, want 60s", unset.registration.VerificationResendInterval)
	}

	var explicit Config
	explicit.registration.VerificationResendInterval = 5 * time.Minute
	explicit.set.registration = true
	explicit.applyDefaults()
	if explicit.registration.VerificationResendInterval != 5*time.Minute {
		t.Errorf("explicit VerificationResendInterval = %v, want 5m", explicit.registration.VerificationResendInterval)
	}

	var off Config
	off.registration.VerificationResendInterval = -time.Second
	off.set.registration = true
	off.applyDefaults()
	if off.registration.VerificationResendInterval != -time.Second {
		t.Errorf("negative VerificationResendInterval = %v, want -1s (opt-out)", off.registration.VerificationResendInterval)
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
	cfg, err := NewConfig(minimalOpts(WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://example.com"}, Cookies: CookieConfig{Name: "app_session"}}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.browser.Cookies.Name != "app_session" {
		t.Errorf("cookie name = %q", cfg.browser.Cookies.Name)
	}
	if cfg.browser.Cookies.RefreshName != "goauth_refresh" {
		t.Errorf("refresh cookie name = %q, want goauth_refresh", cfg.browser.Cookies.RefreshName)
	}
	if cfg.browser.Cookies.Path != "/" {
		t.Errorf("cookie path = %q, want /", cfg.browser.Cookies.Path)
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

		{"dev http derives insecure", EnvironmentDev, "http://localhost:8080", nil, false},
		{"dev https derives secure", EnvironmentDev, "https://localhost:8080", nil, true},
		{"explicit never in dev", EnvironmentDev, "https://example.com", SecureNever(), false},
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
				WithSecret("0123456789abcdef0123456789abcdef"), WithBrowser(BrowserConfig{AllowedOrigins: []string{tt.url}, Cookies: CookieConfig{Secure: tt.set}}), WithMailer(noopMailer{}),
			)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.resolved.cookieSecure != tt.want {
				t.Errorf("cookieSecure = %v, want %v", cfg.resolved.cookieSecure, tt.want)
			}
		})
	}
}

func TestDefaults_NegativeDurationIsAnErrorNotDisabled(t *testing.T) {
	// A negative *time.Duration is a bad value, not another way to spell
	// "off" — only Duration(0) means that.
	_, err := NewConfig(minimalOpts(WithSession(SessionConfig{
		GraceWindow: Duration(-5 * time.Second),
	}))...)
	if err == nil {
		t.Fatal("expected error for a negative grace window")
	}
	if !strings.Contains(err.Error(), "grace_window") {
		t.Errorf("error should name the field, got: %v", err)
	}
}

func TestValidate_RejectsNegativeSessionDurations(t *testing.T) {
	// A hand-built config with a negative value must be rejected by
	// validate, regardless of how it got there.
	cfg := Config{
		app: AppConfig{
			Name:        "Test",
			BaseURL:     "https://example.com",
			Environment: EnvironmentProd,
			Database:    DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		},
		session: SessionConfig{
			TTL:             time.Hour,
			IdleTTL:         time.Hour,
			RefreshTokenTTL: time.Hour,
			TokenTTL:        time.Hour,
			MaxLifetime:     -time.Hour,
		},
		browser:      BrowserConfig{Cookies: CookieConfig{Name: "s"}, AllowedOrigins: []string{"https://example.com"}},
		secret:       "0123456789abcdef0123456789abcdef",
		registration: RegistrationConfig{InviteTTL: time.Hour, VerificationCodeTTL: time.Hour},
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
				WithSecret("0123456789abcdef0123456789abcdef"), WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://example.com"}}), WithSecurity(SecurityConfig{

					AllowHTTPURLs: tt.set,
				}),
				WithMailer(noopMailer{}),
			)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.resolved.allowHTTPURLs != tt.want {
				t.Errorf("allowHTTPURLs = %v, want %v", cfg.resolved.allowHTTPURLs, tt.want)
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
		WithSecret("0123456789abcdef0123456789abcdef"), WithBrowser(BrowserConfig{AllowedOrigins: []string{"http://localhost:8080"}}), WithMailer(noopMailer{}), // custom mailer, no EmailConfig anywhere
	)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.resolved.allowHTTPURLs {
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
		WithSecret("0123456789abcdef0123456789abcdef"), WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://example.com"}}), WithTwoFactor(TwoFactorConfig{DisableAdminTwoFactor: true}),
		// No WithMailer/WithEmail, no RequireEmailVerification/InviteSignup/
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
		WithSecret("0123456789abcdef0123456789abcdef"), WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://example.com"}}),
		// DisableAdminTwoFactor left at its secure zero value (false).
	)
	if err == nil {
		t.Fatal("expected an error: AdminLogin's two-factor challenge still needs a mailer")
	}
	if !strings.Contains(err.Error(), "AdminLogin two-factor") {
		t.Errorf("error = %v, want it to name AdminLogin two-factor as the reason", err)
	}
}

func TestDefaults_NoMailerFails_WhenInviteSignupOn(t *testing.T) {
	_, err := NewConfig(
		WithApp(AppConfig{
			Name:        "app",
			BaseURL:     "https://example.com",
			Environment: EnvironmentProd,
			Database:    DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		}),
		WithSecret("0123456789abcdef0123456789abcdef"), WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://example.com"}}), WithTwoFactor(TwoFactorConfig{DisableAdminTwoFactor: true}),
		WithRegistration(RegistrationConfig{EmailPassword: true, InviteSignup: true}),
	)
	if err == nil {
		t.Fatal("expected an error: InviteSignup needs a mailer even with AdminLogin two-factor disabled")
	}
	if !strings.Contains(err.Error(), "InviteSignup") {
		t.Errorf("error = %v, want it to name InviteSignup as the reason", err)
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
	var cfg Config
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

func TestCSRFToken_AlwaysEnabled(t *testing.T) {
	// Every constructed instance has signed double-submit protection.
	a := buildAuth(t, minimalOpts()...)
	defer a.Close()
	if a.cfg.csrf == nil {
		t.Fatal("double-submit token layer must always be present")
	}
	if len(a.cfg.csrf.Secret) == 0 {
		t.Error("signing secret was not derived into the token config")
	}
}

func TestCSRFToken_Mandatory(t *testing.T) {
	a := buildAuth(t, minimalOpts()...)
	defer a.Close()
	req := httptest.NewRequest("POST", "https://example.com/auth/login", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	h, _ := a.Handler("POST /auth/login")
	h.ServeHTTP(w, req)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "csrf_token_missing") {
		t.Fatalf("missing token accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestRequireCSRF_EnforcesOriginAndBoundToken(t *testing.T) {
	a := buildAuth(t, minimalOpts(WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://client.example"}}))...)
	defer a.Close()
	bootstrap, ok := a.Handler("GET /auth/csrf-token")
	if !ok {
		t.Fatal("bootstrap handler is missing")
	}
	boot := httptest.NewRecorder()
	bootstrap.ServeHTTP(boot, httptest.NewRequest("GET", "https://example.com/auth/csrf-token", nil))
	token := boot.Header().Get("X-CSRF-Token")
	if boot.Code != 200 || token == "" {
		t.Fatal("bootstrap did not provide token")
	}
	for _, tc := range []struct {
		name, origin, referer, token string
		status                       int
	}{
		{"allowed", "https://client.example", "", token, 200},
		{"referer fallback", "", "https://client.example/page", token, 200},
		{"foreign origin", "https://attacker.example", "", token, 403},
		{"origin takes precedence", "https://attacker.example", "https://client.example/page", token, 403},
		{"missing headers", "", "", token, 403},
		{"missing token", "https://client.example", "", "", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ran := false
			h := a.RequireCSRF(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { ran = true; w.WriteHeader(200) }))
			req := httptest.NewRequest("POST", "https://example.com/custom", nil)
			for _, c := range boot.Result().Cookies() {
				req.AddCookie(c)
			}
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Referer", tc.referer)
			req.Header.Set("X-CSRF-Token", tc.token)
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			if response.Code != tc.status || ran != (tc.status == 200) {
				t.Fatalf("status=%d ran=%v body=%s", response.Code, ran, response.Body.String())
			}
		})
	}
}
