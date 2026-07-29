package goauth

import (
	"context"
	"database/sql"
	"net/http"
	"testing"
	"time"
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
	cfg.registration.EnablePassword = true
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
