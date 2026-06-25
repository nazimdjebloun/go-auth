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
	if cfg.AppName != "" {
		t.Error("expected empty AppName in DefaultConfig")
	}
	if cfg.SessionTTL != 30*24*time.Hour {
		t.Errorf("expected SessionTTL 30d, got %v", cfg.SessionTTL)
	}
	if cfg.RefreshTokenTTL != 30*24*time.Hour {
		t.Errorf("expected RefreshTokenTTL 30d, got %v", cfg.RefreshTokenTTL)
	}
	if cfg.TokenTTL != 1*time.Hour {
		t.Errorf("expected TokenTTL 1h, got %v", cfg.TokenTTL)
	}
	if cfg.Cookie.Name != "goauth_session" {
		t.Errorf("expected cookie name goauth_session, got %s", cfg.Cookie.Name)
	}
	if cfg.Cookie.Path != "/" {
		t.Errorf("expected cookie path /, got %s", cfg.Cookie.Path)
	}
}

func TestValidate_EmptyDriver(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: time.Hour, SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty driver")
	}
}

func TestValidate_NoDatabase(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: time.Hour, SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}, Database: DatabaseConfig{Driver: DriverSQLite}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for no database URL, DB, or Pool")
	}
}

func TestValidate_WithDB(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: time.Hour, SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}, Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_EmptyAppName(t *testing.T) {
	cfg := Config{SessionTTL: time.Hour, SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}, Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty app name")
	}
}

func TestValidate_ZeroSessionTTL(t *testing.T) {
	cfg := Config{AppName: "Test", SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}, Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for zero SessionTTL")
	}
}

func TestValidate_IdleTTLExceedsSessionTTL(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: 30 * time.Minute, SessionIdleTTL: time.Hour, RefreshTokenTTL: 30 * time.Minute, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}, Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when IdleTTL > SessionTTL")
	}
}

func TestValidate_RefreshTTLExceedsSessionTTL(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: 30 * time.Minute, SessionIdleTTL: 30 * time.Minute, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}, Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when RefreshTTL > SessionTTL")
	}
}

func TestValidate_EmptyAllowedOrigins(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: time.Hour, SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty allowed origins")
	}
}

func TestValidate_EmptyCookieName(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: time.Hour, SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, AllowedOrigins: []string{"*"}, Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error for empty cookie name")
	}
}

func TestValidate_RequiresEmailWithMailer(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: time.Hour, SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}, RequireEmailVerification: true, Mailer: &mockMailer{}, BaseURL: "http://localhost:3000", Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err != nil {
		t.Fatalf("unexpected error when Mailer is set: %v", err)
	}
}

func TestValidate_RequiresEmailMissingMailer(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: time.Hour, SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}, RequireEmailVerification: true, Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when RequireEmailVerification is true but Mailer and Email are nil")
	}
}

func TestValidate_MailerRequiresBaseURL(t *testing.T) {
	cfg := Config{AppName: "Test", SessionTTL: time.Hour, SessionIdleTTL: time.Hour, RefreshTokenTTL: time.Hour, TokenTTL: time.Hour, Cookie: CookieConfig{Name: "s"}, AllowedOrigins: []string{"*"}, Mailer: &mockMailer{}, Database: DatabaseConfig{Driver: DriverSQLite, DB: &sql.DB{}}}
	err := cfg.validate()
	if err == nil {
		t.Fatal("expected error when Mailer is set but BaseURL is empty")
	}
}

func validConfigOpts() []func(*Config) {
	return []func(*Config){
		func(c *Config) {
			c.AppName = "Test"
			c.Database.Driver = DriverSQLite
			c.Database.URL = "file::memory:?cache=shared"
			c.SessionTTL = 30 * 24 * time.Hour
			c.SessionIdleTTL = 7 * 24 * time.Hour
			c.RefreshTokenTTL = 30 * 24 * time.Hour
			c.TokenTTL = 1 * time.Hour
			c.Cookie.Name = "goauth_session"
			c.AllowedOrigins = []string{"*"}
		},
	}
}

func TestNewConfig_Valid(t *testing.T) {
	cfg, err := NewConfig(validConfigOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AppName != "Test" {
		t.Errorf("expected AppName Test, got %s", cfg.AppName)
	}
}

func TestNewConfig_Invalid(t *testing.T) {
	_, err := NewConfig(func(c *Config) { c.AppName = "" })
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewConfig_OverridesDefault(t *testing.T) {
	cfg, err := NewConfig(
		func(c *Config) {
			c.AppName = "Custom"
			c.Database.Driver = DriverSQLite
			c.Database.URL = "file::memory:?cache=shared"
			c.SessionTTL = 7 * 24 * time.Hour
			c.SessionIdleTTL = 7 * 24 * time.Hour
			c.RefreshTokenTTL = 7 * 24 * time.Hour
			c.TokenTTL = 1 * time.Hour
			c.Cookie.Name = "goauth_session"
			c.AllowedOrigins = []string{"*"}
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL != 7*24*time.Hour {
		t.Errorf("expected SessionTTL 7d, got %v", cfg.SessionTTL)
	}
}

func TestNewConfig_ProviderValidation(t *testing.T) {
	opts := validConfigOpts()
	opts = append(opts, func(c *Config) {
		c.Providers = map[string]ProviderConfig{
			"google": {ClientID: "id"},
		}
	})
	_, err := NewConfig(opts...)
	if err == nil {
		t.Fatal("expected error for provider without ClientSecret and RedirectURL")
	}
}

func TestNewConfig_SameSiteDefault(t *testing.T) {
	cfg, err := NewConfig(validConfigOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSiteLaxMode, got %v", cfg.Cookie.SameSite)
	}
}

// mockMailer is a minimal mock for testing Config.validate when Mailer is set.
type mockMailer struct{}

func (m *mockMailer) Send(_ context.Context, _, _, _, _ string) error { return nil }
