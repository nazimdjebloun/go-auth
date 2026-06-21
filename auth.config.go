// Recommended consumer usage:
//
//	package main
//
//	import (
//	    "log"
//	    "net/http"
//	    "os"
//
//	    "github.com/nazimdjebloun/go-auth"
//	)
//
//	var Auth *goauth.Auth
//
//	func initAuth() {
//	    cfg, err := goauth.NewConfig(
//	        func(c *goauth.Config) {
//	            c.AppName      = os.Getenv("APP_NAME")
//	            c.Database.URL = os.Getenv("DATABASE_URL")
//	        },
//	        func(c *goauth.Config) {
//	            c.Email = &goauth.EmailConfig{
//	                SMTP: goauth.SMTPConfig{
//	                    Host: os.Getenv("SMTP_HOST"),
//	                    Port: 587,
//	                    User: os.Getenv("SMTP_USER"),
//	                    Pass: os.Getenv("SMTP_PASS"),
//	                },
//	                From: os.Getenv("EMAIL_FROM"),
//	            }
//	        },
//	        func(c *goauth.Config) {
//	            c.Cookie.Domain = os.Getenv("COOKIE_DOMAIN")
//	            c.Cookie.Secure = os.Getenv("ENV") == "production"
//	        },
//	    )
//	    if err != nil {
//	        log.Fatalf("goauth config invalid: %v", err)
//	    }
//
//	    Auth, err = goauth.New(cfg)
//	    if err != nil {
//	        log.Fatalf("goauth init failed: %v", err)
//	    }
//	}
//
// Then in main.go:
//
//	func main() {
//	    initAuth()
//	    mux := http.NewServeMux()
//	    Auth.Mount(mux)
//	    log.Fatal(http.ListenAndServe(":8080", mux))
//	}
package goauth

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

type Driver string

const (
	DriverPostgres Driver = "postgres"
	DriverSQLite   Driver = "sqlite3"
	DriverMySQL    Driver = "mysql"
)

const bcryptCost = 12
const tokenLength = 32

// DatabaseConfig configures the database connection.
// Provide one of URL, DB, or Pool. URL is the preferred option —
// the library will open, validate, and close the connection automatically.
type DatabaseConfig struct {
	URL    string        // connection string (preferred)
	DB     *sql.DB       // pre-opened *sql.DB (library borrows, does not close)
	Pool   *pgxpool.Pool // pre-opened pgx pool (library borrows, does not close)
	Driver Driver        // DriverPostgres (default), DriverSQLite, DriverMySQL

	opened bool // internal — true if the library opened the connection
}

// EmailConfig configures SMTP email delivery.
type EmailConfig struct {
	SMTP SMTPConfig
	From string
}

// SMTPConfig holds SMTP server credentials.
type SMTPConfig struct {
	Host string
	Port int
	User string
	Pass string
}

// CookieConfig configures the session cookie.
type CookieConfig struct {
	Name     string
	Domain   string
	Path     string
	Secure   bool
	SameSite http.SameSite
}

// Config is the top-level configuration for go-auth.
// Fields are grouped by concern for readability.
type Config struct {
	// ─── Application ───────────────────────────────────────────────
	AppName string // displayed in email subjects (default "App")

	// ─── Database ──────────────────────────────────────────────────
	Database DatabaseConfig

	// ─── Password Policy ───────────────────────────────────────────
	PasswordPolicy domain.PasswordPolicy

	// ─── Sessions & Tokens ─────────────────────────────────────────
	SessionTTL      time.Duration // absolute hard expiry (default 30d)
	SessionIdleTTL  time.Duration // idle timeout after last activity (default 7d)
	Cookie          CookieConfig
	TokenTTL        time.Duration // how long verification/reset tokens live (default 1h)

	// ─── Email & Verification ──────────────────────────────────────
	RequireEmailVerification bool          // require email verification on signup (default false)
	VerificationCodeTTL      time.Duration // how long verification codes live (default 15m)
	Mailer                   Mailer        // custom mailer implementation (optional)
	Email                    *EmailConfig  // SMTP mailer config (used if Mailer is nil)

	// ─── Invites ───────────────────────────────────────────────────
	InviteOnly bool          // only invited users can register (default false)
	InviteTTL  time.Duration // how long invites last (default 7d)

	// ─── Security ──────────────────────────────────────────────────
	AllowedOrigins []string           // allowed origins for CSRF Origin/Referer check
	RateLimit      *ratelimit.Config  // rate limiting config (optional)
}

func (c Config) validate() error {
	var errs []error

	if c.Database.Driver == "" {
		errs = append(errs, errors.New("database: driver cannot be empty"))
	}
	if c.Database.URL == "" && c.Database.DB == nil && c.Database.Pool == nil {
		errs = append(errs, errors.New("database: one of URL, DB, or Pool is required"))
	}
	if c.AppName == "" {
		errs = append(errs, errors.New("app_name cannot be empty"))
	}
	if c.SessionTTL <= 0 {
		errs = append(errs, errors.New("session_ttl must be positive"))
	}
	if c.SessionIdleTTL <= 0 {
		errs = append(errs, errors.New("session_idle_ttl must be positive"))
	}
	if c.SessionIdleTTL > c.SessionTTL {
		errs = append(errs, errors.New("session_idle_ttl must not exceed session_ttl"))
	}
	if len(c.AllowedOrigins) == 0 {
		errs = append(errs, errors.New("allowed_origins must include at least one origin"))
	}
	if c.TokenTTL <= 0 {
		errs = append(errs, errors.New("token_ttl must be positive"))
	}
	if c.Cookie.Name == "" {
		errs = append(errs, errors.New("cookie name cannot be empty"))
	}

	return errors.Join(errs...)
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		RequireEmailVerification: false,
		InviteTTL:           7 * 24 * time.Hour,
		VerificationCodeTTL: 15 * time.Minute,
		SessionTTL:          30 * 24 * time.Hour,
		SessionIdleTTL:      7 * 24 * time.Hour,
		TokenTTL:            1 * time.Hour,
		PasswordPolicy: domain.PasswordPolicy{
			MinLength:    8,
			RequireDigit: true,
		},
		Cookie: CookieConfig{
			Name:     "goauth_session",
			Path:     "/",
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		},
	}
}

// NewConfig applies the given option functions to DefaultConfig and validates.
// If validation fails, the returned error includes all invalid fields.
func NewConfig(opts ...func(*Config)) (Config, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
