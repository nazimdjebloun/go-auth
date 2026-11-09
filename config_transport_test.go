package goauth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/redis/go-redis/v9"
)

func newServiceOnlyAuth(t *testing.T, options ...Option) (*Auth, *sql.DB) {
	t.Helper()
	db := testdb.Open(t, "sqlite", "")
	if _, err := Migrate(t.Context(), db, MigrationOptions{Driver: "sqlite"}); err != nil {
		t.Fatal(err)
	}
	base := []Option{
		WithTransport(TransportServices),
		WithApp(AppConfig{
			Name: "backend", BaseURL: "https://app.example.com", Database: DatabaseConfig{Driver: DriverSQLite, DB: db},
		}),
		WithSecret("0123456789abcdef0123456789abcdef"), WithMailer(noopMailer{}),
		WithPasswordHashing(PasswordHashingConfig{BcryptCost: 4}),
		WithRegistration(RegistrationConfig{EmailPassword: true, AllowPublic: true}),
	}
	cfg, err := NewConfig(append(base, options...)...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, db
}

func TestServiceOnlyConstructionWithoutBrowserOrURLs(t *testing.T) {
	a, _ := newServiceOnlyAuth(t,
		WithMailer(nil), WithTwoFactor(TwoFactorConfig{DisableAdminTwoFactor: true}),
		func(c *Config) { c.app.BaseURL = "" },
	)
	if len(a.routes) != 0 || a.authMW != nil || a.adminMW != nil || a.rateLimitMW != nil ||
		a.corsMW != nil || a.orgMemberMW != nil || a.cfg.csrf != nil || a.cfg.rateLimit.Store != nil {
		t.Fatal("service-only construction allocated HTTP wiring, CSRF state or an HTTP rate store")
	}
	if a.twoFactorStore == nil || !a.twoFactorStoreOwned || a.maintenance == nil {
		t.Fatal("service-only construction lost service-level support resources")
	}
	d := a.Describe()
	if d.Transport != TransportServices || d.Browser != nil || d.RateLimit.Enabled ||
		d.RateLimit.Store != "disabled" || d.Background.RateLimitCleanup || !d.Background.TwoFactorCleanup {
		t.Fatalf("service-only report: %+v", d)
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"browser"`) {
		t.Fatal("service-only report advertised browser policy")
	}
	registered, err := a.Register(t.Context(), api.RegisterInput{
		Email: "backend@example.test", Password: validTestPassword(), Name: "Backend user",
	})
	if err != nil || registered.SessionToken == "" {
		t.Fatalf("registration without URLs: %v", err)
	}
	if _, err := a.Login(t.Context(), api.LoginInput{
		Email: registered.User.Email, Password: validTestPassword(),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceOnlyHTTPEntryPointsFailClosed(t *testing.T) {
	a, _ := newServiceOnlyAuth(t)
	mux := http.NewServeMux()
	if err := a.Mount(mux); !errors.Is(err, ErrHTTPDisabled) {
		t.Fatalf("Mount error: %v", err)
	}
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest("POST", "/auth/login", nil))
	if response.Code != http.StatusNotFound {
		t.Fatal("failed Mount registered partial HTTP routes")
	}
	if handler, ok := a.Handler("POST /auth/login"); ok || handler != nil {
		t.Fatal("service-only handler lookup succeeded")
	}
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	scoped := func(http.ResponseWriter, *http.Request, OrgScope) { called = true }
	for name, handler := range map[string]http.Handler{
		"auth": a.RequireAuth(next), "admin": a.RequireAdmin(next),
		"rate": a.RateLimit(next), "pattern rate": a.RateLimitWithPattern("POST /app")(next),
		"CORS": a.CORS(next), "CSRF": a.RequireCSRF(next), "Protect": a.Protect("POST /app", next),
		"org":                     a.RequireOrg(domain.OrgRoleMember)(next),
		"active org":              a.RequireActiveOrg(domain.OrgRoleMember)(next),
		"app permission":          a.RequireAppPermission("app.records.read")(next),
		"org permission":          a.RequireOrgPermission("org.records.read")(next),
		"active permission":       a.RequireActiveOrgPermission("org.records.read")(next),
		"org scope":               a.RequireOrgScope(domain.OrgRoleMember, scoped),
		"active scope":            a.RequireActiveOrgScope(domain.OrgRoleMember, scoped),
		"permission scope":        a.RequireOrgPermissionScope("org.records.read", scoped),
		"active permission scope": a.RequireActiveOrgPermissionScope("org.records.read", scoped),
		"protected scope":         a.ProtectOrgScope("POST /app/{orgID}", "org.records.read", scoped),
		"protected active scope":  a.ProtectActiveOrgScope("POST /app", "org.records.read", scoped),
	} {
		t.Run(name, func(t *testing.T) {
			for _, method := range []string{"POST", "OPTIONS"} {
				request := httptest.NewRequest(method, "/app", nil)
				request.Header.Set("Origin", "https://app.example.com")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				var failure domain.AuthError
				if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil {
					t.Fatal(err)
				}
				if response.Code != 503 || failure.Code != ErrHTTPDisabled.Code || called ||
					len(response.Result().Cookies()) != 0 {
					t.Fatalf("disabled helper: status=%d body=%s called=%v", response.Code, response.Body, called)
				}
			}
		})
	}
	for name, operation := range map[string]func(http.ResponseWriter, *http.Request) error{
		"set": func(w http.ResponseWriter, r *http.Request) error {
			return a.SetSessionCookies(w, r, "id", "raw-session", "raw-refresh")
		},
		"clear": a.ClearSessionCookies, "rotate CSRF": a.RotateCSRFToken,
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			err := operation(response, httptest.NewRequest("POST", "/app", nil))
			if !errors.Is(err, ErrHTTPDisabled) || len(response.Header()) != 0 || response.Body.Len() != 0 {
				t.Fatalf("cookie helper wrote an unavailable policy: %v %v", err, response.Header())
			}
		})
	}
	if a.cfg.rateLimit.Store != nil {
		t.Fatal("calling a disabled helper allocated an HTTP rate-limit store")
	}
}

func TestServiceOnlyCoreIdentityAndTenantAuthorization(t *testing.T) {
	a, db := newServiceOnlyAuth(t,
		WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true}),
	)
	owner := registerForScopedRoute(t, a, "service-owner@example.test")
	outsider := registerForScopedRoute(t, a, "service-outsider@example.test")
	actor, err := a.GetActor(t.Context(), owner.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Account(actor).Profile.ChangeName(t.Context(), "Renamed in RPC"); err != nil {
		t.Fatal(err)
	}
	forged := actor
	forged.UserID = outsider.User.ID
	if err := a.Account(forged).Profile.ChangeName(t.Context(), "Forged"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("actor ownership guard changed: %v", err)
	}
	org, err := a.Account(actor).Org.CreateOrg(t.Context(), api.CreateOwnOrgInput{Name: "Tenant", Slug: "tenant"})
	if err != nil {
		t.Fatal(err)
	}
	scope, err := a.AuthorizeOrg(t.Context(), api.CheckOrgPermissionInput{
		Actor: actor.ForOrg(org.ID), PermissionKey: "goauth.org.organization.read",
	})
	if err != nil || scope.OrgID != org.ID || scope.Actor() != actor {
		t.Fatalf("tenant authorization: %+v %v", scope, err)
	}
	outsiderActor, err := a.GetActor(t.Context(), outsider.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if scope, err := a.AuthorizeOrg(t.Context(), api.CheckOrgPermissionInput{
		Actor: outsiderActor.ForOrg(org.ID), PermissionKey: "goauth.org.organization.read",
	}); err == nil || scope != (OrgScope{}) {
		t.Fatalf("nonmember got a tenant scope: %+v %v", scope, err)
	}
	_, err = db.ExecContext(t.Context(), "UPDATE users SET is_banned = $1 WHERE id = $2", true, outsider.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetActor(t.Context(), outsider.SessionToken); !errors.Is(err, domain.ErrUserBanned) {
		t.Fatalf("ban check changed: %v", err)
	}
	account := a.Account(actor)
	if err := account.Session.RevokeAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := account.Profile.ChangeName(t.Context(), "After revocation"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("retained service account survived revocation: %v", err)
	}
}

func TestServiceOnlyKeepsVerificationPolicy(t *testing.T) {
	mailer := &testutil.MockMailer{}
	a, _ := newServiceOnlyAuth(t, WithMailer(mailer), WithRegistration(RegistrationConfig{
		EmailPassword: true, AllowPublic: true, RequireEmailVerification: true,
	}))
	registered, err := a.Register(t.Context(), api.RegisterInput{
		Email: "verify@example.test", Password: validTestPassword(), Name: "Pending",
	})
	if err != nil || !registered.RequiresVerification || registered.Session != nil {
		t.Fatalf("verification policy: %+v %v", registered, err)
	}
	created, err := a.Trusted().Session.Create(t.Context(), api.CreateSessionInput{UserID: registered.User.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetActor(t.Context(), created.SessionToken); !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("service-only credential validation bypassed verification: %v", err)
	}
	code := testutil.GetLastVerificationCode(mailer)
	if _, err := a.Services().Verify.VerifyEmail(t.Context(), code); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetActor(t.Context(), created.SessionToken); err != nil {
		t.Fatalf("verified credential was rejected: %v", err)
	}
}

func TestServiceOnlyKeepsTwoFactorAndBinding(t *testing.T) {
	mailer := &contextCodeMailer{}
	a, _ := newServiceOnlyAuth(t, WithMailer(mailer), WithTwoFactor(TwoFactorConfig{RequireEmail2FA: true}))
	registered, err := a.Register(t.Context(), api.RegisterInput{
		Email: "mfa@example.test", Password: validTestPassword(), Name: "MFA",
	})
	if err != nil || !registered.RequiresTwoFactor || registered.SessionToken != "" ||
		registered.BindingToken() == "" || a.Trusted().TwoFactor.BindingDisabled() {
		t.Fatalf("MFA or binding policy changed: %+v %v", registered, err)
	}
	proof := api.TwoFactorVerifyInput{ChallengeID: registered.TwoFactorChallenge, Code: mailer.last(t)}
	if _, err := a.Services().TwoFactor.Verify(t.Context(), proof); !errors.Is(err, domain.ErrTwoFactorCodeInvalid) {
		t.Fatalf("unbound challenge verified: %v", err)
	}
	proof.BindingToken = registered.BindingToken()
	verified, err := a.Services().TwoFactor.Verify(t.Context(), proof)
	if err != nil || verified.Session == nil || verified.Session.TwoFactorVerifiedAt == nil {
		t.Fatalf("bound MFA proof failed: %+v %v", verified, err)
	}
	if _, err := a.GetActor(t.Context(), verified.SessionToken); err != nil {
		t.Fatal(err)
	}
}

func TestServiceOnlyKeepsDefaultAdminMFA(t *testing.T) {
	mailer := &contextCodeMailer{}
	a, db := newServiceOnlyAuth(t, WithMailer(mailer))
	registered := registerForScopedRoute(t, a, "service-admin@example.test")
	_, err := db.ExecContext(t.Context(), "UPDATE users SET role = $1 WHERE id = $2", "admin", registered.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	login, err := a.Services().Auth.AdminLogin(t.Context(), api.LoginInput{
		Email: registered.User.Email, Password: validTestPassword(),
	})
	if err != nil || !login.RequiresTwoFactor || login.SessionToken != "" {
		t.Fatalf("default administrator MFA was bypassed: %+v %v", login, err)
	}
	verified, err := a.Services().TwoFactor.Verify(t.Context(), api.TwoFactorVerifyInput{
		ChallengeID: login.TwoFactorChallenge, Code: mailer.last(t), BindingToken: login.BindingToken(),
	})
	if err != nil || verified.Session == nil || verified.Session.TwoFactorVerifiedAt == nil {
		t.Fatalf("programmatic admin challenge failed: %+v %v", verified, err)
	}
	if _, err := a.GetActor(t.Context(), verified.SessionToken); err != nil {
		t.Fatal(err)
	}
}

func TestServiceOnlyKeepsOAuthStateBinding(t *testing.T) {
	a, _ := newServiceOnlyAuth(t, WithProvider(&mockProvider{name: "mock"}),
		WithAuthentication(AuthenticationConfig{EmailPassword: true, OAuth: true}),
		WithRegistration(RegistrationConfig{EmailPassword: true, OAuth: true, AllowPublic: true}),
	)
	flow, err := a.Services().OAuth.Initiate(t.Context(), "mock")
	if err != nil {
		t.Fatal(err)
	}
	input := api.OAuthCallbackInput{Provider: "mock", Code: "provider-code", State: flow.State}
	if result, err := a.Services().OAuth.Callback(t.Context(), input); err == nil || result != nil {
		t.Fatal("OAuth callback accepted no initiating-client state proof")
	}
	input.BrowserState = flow.State
	result, err := a.Services().OAuth.Callback(t.Context(), input)
	if err != nil || result.SessionToken == "" {
		t.Fatalf("bound OAuth callback failed: %+v %v", result, err)
	}
	if _, err := a.GetActor(t.Context(), result.SessionToken); err != nil {
		t.Fatal(err)
	}
}

func TestServiceOnlyDoesNotBuildRedisHTTPRateCounters(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "unused:1", ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = client.Close() })
	hook := &redisStartupDeadlineHook{}
	client.AddHook(hook)
	a, _ := newServiceOnlyAuth(t,
		WithRateLimitStore(fakeRateLimitStore{}),
		WithRedis(RedisConfig{
			Client: client, Sessions: boolPtr(false), Tokens: boolPtr(false), TwoFactorNotifications: boolPtr(false),
		}),
	)
	if a.redis.rate != nil || !hook.deadline.IsZero() || a.Describe().Redis.RateLimits {
		t.Fatal("service-only construction attempted HTTP Redis counters")
	}
}

func TestServiceOnlyTransportResolutionAndRevalidation(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(WithTransport(TransportServices))...)
	if err != nil {
		t.Fatal(err)
	}
	// These HTTP-only values are inactive. Selecting browser mode later must
	// validate them rather than inherit a service-only validation decision.
	WithBrowser(BrowserConfig{AllowedOrigins: []string{"*"}})(cfg)
	WithRateLimitDefault(ratelimit.Rate{Requests: -1, Window: time.Minute})(cfg)
	WithRateLimitRoute("GET /DO-NOT-REPORT/{", ratelimit.Rate{Requests: -1})(cfg)
	if d, err := cfg.Describe(); err != nil || d.Transport != TransportServices || d.Browser != nil {
		t.Fatalf("inactive transport configuration: %+v %v", d, err)
	} else if len(d.RateLimit.Routes) != 0 || d.RateLimit.Default.Requests != 0 {
		t.Fatal("service-only report copied inactive HTTP policy")
	}
	WithTransport(TransportBrowser)(cfg)
	_, err = cfg.Describe()
	var failure *ConfigError
	if !errors.As(err, &failure) || !strings.Contains(err.Error(), "Browser.AllowedOrigins[0]") ||
		!strings.Contains(err.Error(), "RateLimit.Default.Requests") {
		t.Fatalf("browser selection skipped validation: %v", err)
	}
	WithTransport(Transport("invalid"))(cfg)
	_, err = cfg.Describe()
	if !errors.As(err, &failure) || failure.Issues[len(failure.Issues)-1].Field != "Transport" {
		t.Fatalf("invalid transport was accepted: %v", err)
	}
}

func TestServiceOnlyDefaultMailerPolicyIsPreserved(t *testing.T) {
	opts := []Option{
		WithTransport(TransportServices), WithApp(AppConfig{
			Name: "worker", Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		}), WithSecret("0123456789abcdef0123456789abcdef"),
	}
	if _, err := NewConfig(opts...); err == nil || !strings.Contains(err.Error(), "Email") {
		t.Fatalf("service-only mode disabled mandatory admin MFA/mail policy: %v", err)
	}
	opts = append(opts, WithTwoFactor(TwoFactorConfig{DisableAdminTwoFactor: true}))
	if _, err := NewConfig(opts...); err != nil {
		t.Fatalf("mail-free service-only configuration needs fake URLs: %v", err)
	}
	opts = append(opts, WithMailer(noopMailer{}))
	if _, err := NewConfig(opts...); err == nil || !strings.Contains(err.Error(), "App.BaseURL") {
		t.Fatalf("configured email accepted no application link origin: %v", err)
	}
}

func TestTransportConfigReuseKeepsExistingBrowserProtected(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	before := f.a.Describe()
	cfg := f.a.cfg.clone()
	WithTransport(TransportServices)(&cfg)
	service, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	if !reflect.DeepEqual(f.a.Describe(), before) || service.Describe().Browser != nil || service.cfg.csrf != nil {
		t.Fatal("service construction changed the existing browser instance")
	}
	called := false
	f.mux.Handle("POST /transport-check", f.a.Protect("POST /transport-check",
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(204) })))
	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/transport-check", nil)
	request.Header.Set("Origin", "http://localhost")
	f.mux.ServeHTTP(response, request)
	if response.Code != 403 || called {
		t.Fatal("browser instance lost mandatory CSRF after service construction")
	}
	f.request(t, "POST", "/transport-check", "", f.token, 204)
	if !called {
		t.Fatal("valid protected browser request failed")
	}
}
