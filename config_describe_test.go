package goauth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/provider/google"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/redis/go-redis/v9"
)

func TestConfigDescribeResolvesLateOptionsWithoutMutationOrWorkers(t *testing.T) {
	cfg, err := NewConfig(minimalOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	// Whole-section replacement clears earlier fields; amendments then build on it.
	WithBrowser(BrowserConfig{
		APIURL: "https://discarded.example.com", AllowedOrigins: []string{"https://discarded.example.com"},
	})(cfg)
	WithBrowser(BrowserConfig{AllowedOrigins: []string{"https://frontend.example.com"}})(cfg)
	WithSession(SessionConfig{TTL: 10 * time.Hour})(cfg)
	WithSession(SessionConfig{GraceWindow: Duration(0), TouchDebounce: Duration(0)})(cfg)
	WithRateLimitStore(fakeRateLimitStore{})(cfg)
	WithRateLimit(*ratelimit.DefaultRateLimitConfig())(cfg) // replaces the supplied store
	WithTrustedIPs([]string{"192.0.2.1"})(cfg)
	cfg.rateLimit.DisabledRoutes = []string{"GET /reports"}
	WithRateLimitRoute("GET /reports", ratelimit.Rate{Requests: 7, Window: time.Minute})(cfg)
	before := memoryStoreWorkers(t)
	for range 3 {
		d, err := cfg.Describe()
		if err != nil {
			t.Fatal(err)
		}
		if d.Browser.APIURL != "https://example.com" || !d.Browser.Cookies.Secure ||
			d.Browser.Cookies.SameSite != "lax" || !d.Browser.Cookies.HTTPOnly {
			t.Fatalf("derived browser policy: %+v", d.Browser)
		}
		if d.Session.TTL != (30*24*time.Hour).String() || d.Session.GraceWindow != "0s" ||
			d.Session.TouchDebounce != "0s" || d.Session.MaxLifetime != "0s" {
			t.Fatalf("resolved session policy: %+v", d.Session)
		}
		if d.RateLimit.Store != "memory" || d.RateLimit.Routes["GET /reports"].Requests != 7 {
			t.Fatalf("resolved amended policy: %+v", d.RateLimit)
		}
		if !d.Background.Maintenance || !d.Background.RecoveryEmail || !d.Background.TwoFactorCleanup ||
			d.Background.AuditDelivery || d.Background.AuditRetention {
			t.Fatalf("default work: %+v", d.Background)
		}
		// Mutating a report must never configure the library.
		d.Browser.AllowedOrigins[0] = "https://forged.example.com"
		d.RateLimit.Routes["GET /reports"] = RateDescription{Requests: 999}
		d.RateLimit.TrustedIPs[0] = "203.0.113.1"
		d.RateLimit.DisabledRoutes[0] = "GET /forged"
	}
	if cfg.session.TTL != 0 || cfg.browser.APIURL != "" || cfg.rateLimit.Store != nil ||
		cfg.browser.AllowedOrigins[0] != "https://frontend.example.com" ||
		cfg.rateLimit.TrustedIPs[0] != "192.0.2.1" || cfg.rateLimit.DisabledRoutes[0] != "GET /reports" {
		t.Fatal("description defaulting or mutation changed consumer configuration")
	}
	if memoryStoreWorkers(t) != before {
		t.Fatal("configuration inspection allocated memory-store cleanup workers")
	}
}

func TestConfigDescribeRejectsUnvalidatedAndInvalidLateOptions(t *testing.T) {
	for _, cfg := range []*Config{nil, {}} {
		if d, err := cfg.Describe(); err == nil || !reflect.DeepEqual(d, ConfigDescription{}) {
			t.Fatalf("unvalidated configuration returned a description: %+v, %v", d, err)
		}
	}
	cfg, err := NewConfig(minimalOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	WithSecret("short")(cfg)
	WithSession(SessionConfig{TTL: -time.Second})(cfg)
	d, err := cfg.Describe()
	if err == nil || !strings.Contains(err.Error(), "secret") || !strings.Contains(err.Error(), "session") ||
		!reflect.DeepEqual(d, ConfigDescription{}) {
		t.Fatalf("late invalid options were described as valid: %+v, %v", d, err)
	}
}

func TestConfigDescribeDatabaseOwnershipAndEffectiveLimits(t *testing.T) {
	zero := 0
	for _, tc := range []struct {
		name     string
		database DatabaseConfig
		source   string
		closeSQL bool
		open     int
		idle     int
	}{
		{
			name: "postgres defaults", database: DatabaseConfig{Driver: DriverPostgres, URL: "unused"},
			source: "url", closeSQL: true, open: 25, idle: 2,
		},
		{
			name: "mysql defaults", database: DatabaseConfig{Driver: DriverMySQL, URL: "unused"},
			source: "url", closeSQL: true, open: 25, idle: 2,
		},
		{
			name: "sqlite defaults", database: DatabaseConfig{Driver: DriverSQLite, URL: ":memory:"},
			source: "url", closeSQL: true, open: 1, idle: 1,
		},
		{
			name: "explicit zero idle",
			database: DatabaseConfig{
				Driver: DriverPostgres, URL: "unused", MaxOpenConns: 8, MaxIdleConns: &zero,
				ConnMaxLifetime: time.Hour, ConnMaxIdleTime: time.Minute,
			},
			source: "url", closeSQL: true, open: 8,
		},
		{
			name:     "borrowed db ignores configured limits",
			database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}, MaxOpenConns: 9}, source: "db",
		},
		{
			name:     "borrowed pgx pool owns only SQL adapter",
			database: DatabaseConfig{Driver: DriverPostgres, Pool: &pgxpool.Pool{}}, source: "pool", closeSQL: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(minimalOpts(WithApp(AppConfig{
				Name: "app", BaseURL: "https://example.com", Database: tc.database,
			}))...)
			if err != nil {
				t.Fatal(err)
			}
			d, err := cfg.Describe()
			if err != nil {
				t.Fatal(err)
			}
			if d.Database.Source != tc.source || d.Database.Driver != tc.database.Driver ||
				d.Database.CloseSQLHandle != tc.closeSQL || d.Database.CloseSuppliedPool {
				t.Fatalf("ownership: %+v", d.Database)
			}
			if tc.source != "url" {
				if d.Database.URLLimits != nil {
					t.Fatal("advertised library-applied limits for a borrowed handle")
				}
				return
			}
			limits := d.Database.URLLimits
			if limits == nil || limits.MaxOpenConns != tc.open || limits.MaxIdleConns != tc.idle ||
				limits.ConnMaxLifetime != tc.database.ConnMaxLifetime.String() ||
				limits.ConnMaxIdleTime != tc.database.ConnMaxIdleTime.String() {
				t.Fatalf("effective limits: %+v", limits)
			}
		})
	}
}

func TestDescribeMatchesConstructedCapabilitiesAndReusableConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		options []Option
	}{
		{name: "default"},
		{name: "database-only audit", options: []Option{WithAudit(AuditConfig{Enabled: true})}},
		{
			name: "optional capabilities and delivery",
			options: []Option{
				WithOrganizations(OrganizationConfig{Enable: true}),
				WithAppPermissions(AppPermissionsConfig{Enable: true, EnableManagementHTTP: true}),
				WithOrgPermissions(OrgPermissionsConfig{Enable: true, EnableManagementHTTP: true}),
				WithProvider(&mockProvider{name: "mock"}), WithSecurity(SecurityConfig{AllowEmailChange: true}),
				WithAudit(AuditConfig{Enabled: true, RetentionDays: 31, Sinks: []audit.EventSink{startupBoundedSink{}}}),
			},
		},
		{
			name: "disabled optional work",
			options: []Option{
				WithRateLimitEnabled(false), WithMaintenance(MaintenanceConfig{Disable: true}),
				WithMailer(nil), WithTwoFactor(TwoFactorConfig{DisableAdminTwoFactor: true}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testdb.Open(t, "sqlite", "")
			if _, err := Migrate(t.Context(), db, MigrationOptions{Driver: "sqlite"}); err != nil {
				t.Fatal(err)
			}
			options := minimalOpts(WithApp(AppConfig{
				Name: "app", BaseURL: "https://example.com", Database: DatabaseConfig{Driver: DriverSQLite, DB: db},
			}), WithPasswordHashing(PasswordHashingConfig{BcryptCost: 4}))
			cfg, err := NewConfig(append(options, tc.options...)...)
			if err != nil {
				t.Fatal(err)
			}
			before, err := cfg.Describe()
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				a, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(a.Close)
				d := a.Describe()
				if !reflect.DeepEqual(d, before) {
					t.Fatalf("startup and config report differ: %+v / %+v", d, before)
				}
				s := a.Services()
				if d.Capabilities.EmailChange != (s.Email != nil) || d.Capabilities.OAuth != (s.OAuth != nil) ||
					d.Capabilities.Organizations != (s.Org != nil) ||
					d.Capabilities.AppPermissions != (s.AppPermissions != nil) ||
					d.Capabilities.OrgPermissions != (s.OrgPermissions != nil) ||
					d.Capabilities.Audit != (a.auditService != nil) {
					t.Fatalf("report does not match wired services: %+v", d.Capabilities)
				}
				if d.Background.RecoveryEmail != (a.recoveryWorker != nil) ||
					d.Background.Maintenance != (a.maintenance.cancel != nil) ||
					d.Background.TwoFactorCleanup != a.twoFactorStoreOwned {
					t.Fatalf("report does not match library work: %+v", d.Background)
				}
				wantDelivery := tc.name == "optional capabilities and delivery"
				if d.Background.AuditDelivery != wantDelivery || d.Background.AuditRetention != wantDelivery {
					t.Fatalf("audit work: %+v", d.Background)
				}
				d.Browser.AllowedOrigins[0] = "https://forged.example.com"
				d.RateLimit.Routes["GET /forged"] = RateDescription{Requests: 999}
				if !reflect.DeepEqual(a.Describe(), before) {
					t.Fatal("returned description changed constructed configuration")
				}
				WithSession(SessionConfig{TTL: time.Hour, IdleTTL: time.Hour})(cfg)
				if !reflect.DeepEqual(a.Describe(), before) {
					t.Fatal("later options changed a constructed instance")
				}
				WithSession(SessionConfig{})(cfg) // restore defaults for the second construction
			}
		})
	}
}

func TestDescribeURLLimitsMatchOpenedDatabase(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "description.db") + "?_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := Migrate(t.Context(), db, MigrationOptions{Driver: "sqlite"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	cfg, err := NewConfig(minimalOpts(
		WithApp(AppConfig{
			Name: "app", BaseURL: "https://example.com",
			Database: DatabaseConfig{Driver: DriverSQLite, URL: dsn, MaxOpenConns: 3},
		}),
		WithPasswordHashing(PasswordHashingConfig{BcryptCost: 4}),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	d := a.Describe()
	if d.Database.Source != "url" || !d.Database.CloseSQLHandle || d.Database.URLLimits == nil ||
		d.Database.URLLimits.MaxOpenConns != a.db.Stats().MaxOpenConnections {
		t.Fatalf("report differs from opened connection: %+v", d.Database)
	}
	d.Database.URLLimits.MaxOpenConns = 999
	beforeClose := a.Describe()
	if beforeClose.Database.URLLimits.MaxOpenConns != 3 {
		t.Fatal("description retained a mutable limits pointer")
	}
	a.Close()
	if !reflect.DeepEqual(a.Describe(), beforeClose) {
		t.Fatal("startup policy changed after Close")
	}
	if err := a.db.Ping(); err == nil {
		t.Fatal("owned SQL handle did not follow the reported shutdown policy")
	}
}

func TestConfigDescribeRateStoresAndRedisWithoutConnections(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "unused:1", ContextTimeoutEnabled: true})
	t.Cleanup(func() { _ = client.Close() })
	for _, tc := range []struct {
		name    string
		options []Option
		store   string
		notify  bool
	}{
		{name: "memory", store: "memory"},
		{name: "custom", store: "custom", options: []Option{WithRateLimitStore(fakeRateLimitStore{})}},
		{name: "disabled", store: "disabled", options: []Option{WithRateLimitEnabled(false)}},
		{
			name: "redis", store: "redis", notify: true,
			options: []Option{WithRedis(RedisConfig{Client: client, Tokens: boolPtr(false)})},
		},
		{
			name: "redis with disabled rate", store: "disabled", notify: true,
			options: []Option{WithRedis(RedisConfig{Client: client}), WithRateLimitEnabled(false)},
		},
		{
			name: "custom with redis snapshots only", store: "custom",
			options: []Option{
				WithRateLimitStore(fakeRateLimitStore{}),
				WithRedis(RedisConfig{
					Client: client, RateLimits: boolPtr(false), TwoFactorNotifications: boolPtr(false),
				}),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(minimalOpts(tc.options...)...)
			if err != nil {
				t.Fatal(err)
			}
			d, err := cfg.Describe()
			if err != nil {
				t.Fatal(err)
			}
			memory := tc.store == "memory"
			if d.RateLimit.Store != tc.store || d.RateLimit.CloseStoreOnShutdown != memory ||
				d.Background.RateLimitCleanup != memory || d.Redis.TwoFactorNotifications != tc.notify ||
				d.Background.TwoFactorCleanup == tc.notify || d.Redis.RateLimits != (tc.store == "redis") {
				t.Fatalf("store/worker selection: %+v / %+v / %+v", d.RateLimit, d.Redis, d.Background)
			}
			if tc.name == "redis" && (!d.Redis.Sessions || d.Redis.Tokens) {
				t.Fatalf("Redis capability selection: %+v", d.Redis)
			}
		})
	}
}

type sensitiveDescriptionMailer struct{ noopMailer }

func (sensitiveDescriptionMailer) String() string { panic("description formatted a live mailer") }

func TestDescribeOmitsCredentialsAndLiveObjectsInEveryRepresentation(t *testing.T) {
	root := strings.Repeat("ROOT-SECRET-", 4)
	pepper := strings.Repeat("PEPPER-SECRET-", 4)
	throwaway := uuid.NewString()
	dsn := fmt.Sprintf("postgres://dsn-user-%s:dsn-password-%s@unused:1/private-database", throwaway, throwaway)
	var logs bytes.Buffer
	cfg, err := NewConfig(minimalOpts(
		WithApp(AppConfig{
			Name: "app", BaseURL: "https://example.com/private-link-path",
			Database: DatabaseConfig{Driver: DriverPostgres, URL: dsn},
		}),
		WithSecret(root), WithMailer(sensitiveDescriptionMailer{}),
		WithEmail(EmailConfig{Host: "SMTP-HOST", User: "SMTP-USER", Pass: "SMTP-PASSWORD"}),
		WithProvider(google.New(google.Config{
			ClientID: "OAUTH-CLIENT-ID", ClientSecret: "oauth-secret-" + throwaway, RedirectURL: "https://example.com/callback",
		})),
		WithPasswordHashing(PasswordHashingConfig{
			Pepper: PasswordPepperConfig{CurrentVersion: 1, Keys: map[uint32]string{1: pepper}},
		}),
		WithLogger(slog.New(slog.NewTextHandler(&logs, nil))),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := cfg.Describe()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("config", "auth", d)
	representations := []string{string(encoded), fmt.Sprintf("%v %+v %#v", d, d, d), logs.String()}
	for _, output := range representations {
		for _, forbidden := range []string{
			root, pepper, dsn, "dsn-password-" + throwaway, "dsn-user-" + throwaway, "SMTP-HOST", "SMTP-USER", "SMTP-PASSWORD",
			"OAUTH-CLIENT-ID", "oauth-secret-" + throwaway, "private-link-path", "sensitiveDescriptionMailer",
		} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("description leaked %q", forbidden)
			}
		}
	}
	// Any interface/function/object field added in future must be consciously
	// reviewed, even if today's secret markers did not exercise that field.
	assertDescriptionDataOnly(t, reflect.TypeFor[ConfigDescription]())
}

func assertDescriptionDataOnly(t *testing.T, typ reflect.Type) {
	t.Helper()
	switch typ.Kind() {
	case reflect.Bool, reflect.Int, reflect.String:
	case reflect.Pointer, reflect.Slice:
		assertDescriptionDataOnly(t, typ.Elem())
	case reflect.Map:
		assertDescriptionDataOnly(t, typ.Key())
		assertDescriptionDataOnly(t, typ.Elem())
	case reflect.Struct:
		for field := range typ.NumField() {
			f := typ.Field(field)
			if !f.IsExported() || f.Tag.Get("json") == "" {
				t.Fatalf("unreviewed description field: %s.%s", typ, f.Name)
			}
			assertDescriptionDataOnly(t, f.Type)
		}
	default:
		t.Fatalf("description contains a live/opaque type: %s", typ)
	}
}

func TestDescribeDevelopmentCookiePolicy(t *testing.T) {
	cfg, err := NewConfig(minimalOpts(
		WithApp(AppConfig{
			Name: "app", Environment: EnvironmentDev, BaseURL: "http://localhost:3000",
			Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}},
		}),
		WithBrowser(BrowserConfig{
			AllowedOrigins: []string{"http://localhost:3000"}, Cookies: CookieConfig{SameSite: http.SameSiteStrictMode},
		}),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := cfg.Describe()
	if err != nil {
		t.Fatal(err)
	}
	if d.Environment != EnvironmentDev || d.Browser.APIURL != "http://localhost:3000" ||
		d.Browser.Cookies.Secure || d.Browser.Cookies.SameSite != "strict" {
		t.Fatalf("development derivation: %+v", d.Browser)
	}
}
