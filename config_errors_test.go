package goauth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/provider/google"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"golang.org/x/oauth2"
)

func TestConfigIssuePublicPathsAndCodes(t *testing.T) {
	var nilProvider *mockProvider
	for _, tc := range []struct {
		name    string
		options []Option
		field   string
		code    ConfigIssueCode
	}{
		{"missing secret", []Option{WithSecret("")}, "Secret", ConfigRequired},
		{"short secret", []Option{WithSecret("short")}, "Secret", ConfigRange},
		{
			"missing database", []Option{WithApp(AppConfig{Name: "app", BaseURL: "https://example.com"})},
			"App.Database", ConfigRequired,
		},
		{
			"unsupported driver", []Option{func(c *Config) { c.app.Database.Driver = "other" }},
			"App.Database.Driver", ConfigUnsupported,
		},
		{
			"conflicting database sources", []Option{func(c *Config) { c.app.Database.URL = "unused" }},
			"App.Database", ConfigConflict,
		},
		{
			"invalid origin", []Option{WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://example.com/path"}})},
			"Browser.AllowedOrigins[0]", ConfigInvalid,
		},
		{
			"plaintext API origin",
			[]Option{WithBrowser(BrowserConfig{APIURL: "http://example.com", AllowedOrigins: []string{"https://example.com"}})},
			"Browser.APIURL", ConfigInsecure,
		},
		{
			"duplicate cookie",
			[]Option{WithBrowser(BrowserConfig{
				AllowedOrigins: []string{"https://example.com"}, Cookies: CookieConfig{RefreshName: "goauth_session"},
			})},
			"Browser.Cookies.RefreshName", ConfigDuplicate,
		},
		{
			"CORS list index",
			[]Option{WithBrowser(BrowserConfig{
				AllowedOrigins: []string{"https://example.com"}, CORS: CORSConfig{AllowedHeaders: []string{"X-Good", "*"}},
			})},
			"Browser.CORS.AllowedHeaders[1]", ConfigInvalid,
		},
		{"negative session", []Option{WithSession(SessionConfig{TTL: -time.Second})}, "Session.TTL", ConfigRange},
		{
			"idle lifetime conflict", []Option{WithSession(SessionConfig{TTL: time.Hour, IdleTTL: 2 * time.Hour})},
			"Session.IdleTTL", ConfigConflict,
		},
		{
			"password concurrency", []Option{WithPasswordHashing(PasswordHashingConfig{Concurrency: -1})},
			"PasswordHashing.Concurrency", ConfigRange,
		},
		{
			"pepper version path", []Option{WithPasswordHashing(PasswordHashingConfig{
				Pepper: PasswordPepperConfig{Keys: map[uint32]string{2: "short"}},
			})},
			"PasswordHashing.Pepper.Keys[2]", ConfigRange,
		},
		{
			"empty authentication", []Option{WithAuthentication(AuthenticationConfig{})},
			"Authentication", ConfigRequired,
		},
		{
			"provider dependency", []Option{WithAuthentication(AuthenticationConfig{OAuth: true})},
			"Authentication.OAuth", ConfigDependency,
		},
		{
			"signup lifetime", []Option{WithRegistration(RegistrationConfig{InviteTTL: -time.Second})},
			"Registration.InviteTTL", ConfigRange,
		},
		{
			"two-factor lifetime", []Option{WithTwoFactor(TwoFactorConfig{CodeTTL: -time.Second})},
			"TwoFactor.CodeTTL", ConfigRange,
		},
		{
			"organization limit", []Option{WithOrganizations(OrganizationConfig{Enable: true, MaxOrgsPerUser: 101})},
			"Organizations.MaxOrgsPerUser", ConfigRange,
		},
		{
			"app management dependency", []Option{WithAppPermissions(AppPermissionsConfig{EnableManagementHTTP: true})},
			"AppPermissions.EnableManagementHTTP", ConfigDependency,
		},
		{
			"org permission dependency", []Option{WithOrgPermissions(OrgPermissionsConfig{Enable: true})},
			"OrgPermissions.Enable", ConfigDependency,
		},
		{
			"maintenance interval", []Option{WithMaintenance(MaintenanceConfig{Interval: -time.Second})},
			"Maintenance.Interval", ConfigRange,
		},
		{
			"SMTP host", []Option{WithMailer(nil), WithEmail(EmailConfig{Port: 587, From: "auth@example.com"})},
			"Email.Host", ConfigRequired,
		},
		{
			"missing mailer", []Option{WithMailer(nil)}, "Email", ConfigDependency,
		},
		{"typed-nil provider", []Option{WithProvider(nilProvider)}, "Providers[0]", ConfigRequired},
		{
			"missing provider secret", []Option{WithProvider(google.New(google.Config{ClientID: "client"}))},
			"Providers[0].ClientSecret", ConfigRequired,
		},
		{
			"nil OAuth configuration", []Option{WithProvider(&nilOAuthConfigProvider{mockProvider{name: "test"}})},
			"Providers[0]", ConfigRequired,
		},
		{
			"default rate", []Option{WithRateLimitDefault(ratelimit.Rate{Requests: -1, Window: time.Minute})},
			"RateLimit.Default.Requests", ConfigRange,
		},
		{
			"route budget", []Option{WithRateLimitRoute("GET /reports", ratelimit.Rate{Requests: -1})},
			"RateLimit.Routes", ConfigRange,
		},
		{
			"trusted IP index", []Option{WithTrustedIPs([]string{"invalid"})},
			"RateLimit.TrustedIPs[0]", ConfigInvalid,
		},
		{
			"Redis adapter", []Option{WithRedis(RedisConfig{})}, "Redis", ConfigInvalid,
		},
		{
			"Redis startup timeout", []Option{WithRedis(RedisConfig{StartupTimeout: -time.Second})},
			"Redis.StartupTimeout", ConfigRange,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(minimalOpts(tc.options...)...)
			if cfg != nil {
				t.Fatal("invalid configuration produced a usable config")
			}
			var failure *ConfigError
			if !errors.As(err, &failure) {
				t.Fatalf("expected structured configuration failure, got %v", err)
			}
			found := false
			for _, issue := range failure.Issues {
				if issue.Field == "Config" || issue.Field == "" || issue.Message == "" {
					t.Fatalf("validator lost its field or explanation: %+v", issue)
				}
				found = found || (issue.Field == tc.field && issue.Code == tc.code)
			}
			if !found {
				t.Fatalf("missing %s/%s in %+v", tc.field, tc.code, failure.Issues)
			}
		})
	}
}

type nilOAuthConfigProvider struct{ mockProvider }

func (*nilOAuthConfigProvider) OAuth2Config() *oauth2.Config { return nil }

func TestConfigErrorAggregatesAllSectionsAndNestedGroups(t *testing.T) {
	_, err := NewConfig(minimalOpts(
		WithSecret("short"),
		WithSession(SessionConfig{TTL: -time.Second, IdleTTL: -time.Second}),
		WithBrowser(BrowserConfig{AllowedOrigins: []string{"bad", "http://example.com"}}),
		WithMaintenance(MaintenanceConfig{Interval: -time.Second}),
		WithPasswordHashing(PasswordHashingConfig{Pepper: PasswordPepperConfig{
			CurrentVersion: 3, Keys: map[uint32]string{0: "short", 1: "short", 2: "short"},
		}}),
		func(c *Config) {
			c.app.Database.MaxOpenConns = -1
			c.app.Database.ConnMaxLifetime = -time.Second
			c.app.Database.ConnMaxIdleTime = -time.Second
		},
	)...)
	var failure *ConfigError
	if !errors.As(err, &failure) {
		t.Fatalf("missing aggregate error: %v", err)
	}
	want := map[string]bool{
		"Secret": false, "Session.TTL": false, "Session.IdleTTL": false,
		"Browser.AllowedOrigins[0]": false, "Browser.AllowedOrigins[1]": false,
		"Maintenance.Interval": false, "PasswordHashing.Pepper.CurrentVersion": false,
		"PasswordHashing.Pepper.Keys[0]": false, "PasswordHashing.Pepper.Keys[1]": false,
		"PasswordHashing.Pepper.Keys[2]": false, "App.Database.MaxOpenConns": false,
		"App.Database.ConnMaxLifetime": false, "App.Database.ConnMaxIdleTime": false,
	}
	for _, issue := range failure.Issues {
		if _, expected := want[issue.Field]; expected {
			want[issue.Field] = true
		}
	}
	for field, found := range want {
		if !found || !strings.Contains(err.Error(), field) {
			t.Errorf("aggregate lost %s: %v", field, err)
		}
	}
}

func TestConfigErrorSurvivesStartupAndDescriptionWrapping(t *testing.T) {
	cfg, err := NewConfig(minimalOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	WithSecret("short")(cfg)
	_, describeErr := cfg.Describe()
	a, startupErr := New(cfg)
	if a != nil {
		a.Close()
		t.Fatal("invalid config constructed an Auth")
	}
	var want []ConfigIssue
	for _, err := range []error{describeErr, startupErr, fmt.Errorf("application startup: %w", startupErr)} {
		var failure *ConfigError
		var issue *ConfigIssue
		if !errors.As(err, &failure) || !errors.As(err, &issue) {
			t.Fatalf("wrapping lost configuration type: %v", err)
		}
		if issue.Field != "Secret" || issue.Code != ConfigRange || !errors.Is(err, failure.Unwrap()[0]) {
			t.Fatalf("wrapping lost issue metadata/traversal: %+v", issue)
		}
		if want == nil {
			want = failure.Issues
		} else if !reflect.DeepEqual(want, failure.Issues) {
			t.Fatal("startup and description disagree on final configuration validation")
		}
	}
	for _, cfg := range []*Config{nil, {}} {
		_, err := cfg.Describe()
		var failure *ConfigError
		if !errors.As(err, &failure) || len(failure.Issues) != 1 || failure.Issues[0].Field != "Config" {
			t.Fatalf("invalid root config was not classified: %v", err)
		}
	}
}

func TestConfigErrorPresentationIsDeterministic(t *testing.T) {
	var baseline string
	for range 40 {
		rl := *ratelimit.DefaultRateLimitConfig()
		rl.Routes = map[string]ratelimit.Rate{
			"GET /a": {Requests: -1, Window: -time.Second},
			"GET /b": {Requests: -2, Window: -time.Minute},
		}
		_, err := NewConfig(minimalOpts(WithRateLimit(rl), WithSecret("short"))...)
		var failure *ConfigError
		if !errors.As(err, &failure) {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(failure)
		if err != nil {
			t.Fatal(err)
		}
		presentation := failure.Error() + string(encoded)
		if baseline == "" {
			baseline = presentation
		} else if presentation != baseline {
			t.Fatal("map iteration changed diagnostic ordering")
		}
	}
}

func TestConfigErrorsOmitSubmittedStringsAndCredentials(t *testing.T) {
	const marker = "DO-NOT-LOG-CREDENTIAL"
	_, err := NewConfig(minimalOpts(
		WithSecret(marker), WithMailer(nil),
		WithApp(AppConfig{
			Name: "app", Environment: Environment(marker), BaseURL: "https://example.com",
			Database: DatabaseConfig{Driver: Driver(marker), URL: "postgres://user:" + marker + "@example.com/db"},
		}),
		WithBrowser(BrowserConfig{
			AllowedOrigins: []string{"https://user:" + marker + "@example.com"},
			CORS:           CORSConfig{AllowedHeaders: []string{marker + "\r\n"}},
			Cookies:        CookieConfig{Name: marker + "\n"},
		}),
		WithPasswordHashing(PasswordHashingConfig{
			Pepper: PasswordPepperConfig{CurrentVersion: 1, Keys: map[uint32]string{1: marker}},
		}),
		WithEmail(EmailConfig{Host: marker, User: marker, Pass: marker, From: marker + " invalid"}),
		WithProvider(&mockProvider{name: marker}), WithProvider(&mockProvider{name: marker}),
		WithRateLimitRoute("GET /"+marker+"/{", ratelimit.Rate{Requests: -1}),
		WithTrustedIPs([]string{marker}),
	)...)
	var failure *ConfigError
	if !errors.As(err, &failure) {
		t.Fatalf("missing structured failure: %v", err)
	}
	encoded, marshalErr := json.Marshal(failure)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Error("configuration rejected", "issues", failure.Issues)
	for _, representation := range []string{
		err.Error(), string(encoded), logs.String(), fmt.Sprintf("%v %+v %#v", failure, failure, failure),
		fmt.Sprintf("%+v", failure.Unwrap()),
	} {
		if strings.Contains(representation, marker) {
			t.Fatal("configuration diagnostics echoed a submitted string or credential")
		}
	}
}

func TestConfigErrorsDoNotClassifyConnectivityOrSchemaFailures(t *testing.T) {
	for _, closed := range []bool{true, false} {
		db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = db.Close() })
		if closed {
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
		}
		cfg, err := NewConfig(minimalOpts(
			WithApp(AppConfig{
				Name: "app", BaseURL: "https://example.com", Database: DatabaseConfig{Driver: DriverSQLite, DB: db},
			}),
			WithPasswordHashing(PasswordHashingConfig{BcryptCost: 4}),
		)...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cfg.Describe(); err != nil {
			t.Fatalf("inspection contacted an unavailable/unmigrated database: %v", err)
		}
		a, err := New(cfg)
		if a != nil {
			a.Close()
			t.Fatal("construction accepted an unavailable/unmigrated database")
		}
		var failure *ConfigError
		if err == nil || errors.As(err, &failure) {
			t.Fatalf("infrastructure failure was classified as configuration: %v", err)
		}
		if closed && !errors.Is(err, sql.ErrConnDone) && !strings.Contains(err.Error(), "database is closed") {
			t.Fatalf("connectivity failure lost its cause: %v", err)
		}
	}
}
