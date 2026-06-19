package goauth

import (
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

type Config struct {
	AppName     string
	AdminEmails []string

	Database  DatabaseConfig
	Mailer    Mailer
	Email     *EmailConfig
	RateLimit *ratelimit.Config

	InviteOnly              bool
	RequireEmailVerification bool
	InviteTTL               time.Duration
	VerificationCodeTTL     time.Duration
	SessionTTL              time.Duration
	TokenTTL                time.Duration
	BcryptCost              int
	TokenLength             int

	AllowedOrigins []string // for Origin/Referer CSRF validation on cookie auth
}

type DatabaseConfig struct {
	Pool   *pgxpool.Pool // pgx pool (session repo uses this directly)
	DB     *sql.DB       // standard DB (sqlstore repos use this)
	Driver string        // "postgres", "mysql", "sqlite3"
	URL    string        // connection string (used if Pool and DB are nil)
}

type EmailConfig struct {
	SMTP SMTPConfig
	From string
}

type SMTPConfig struct {
	Host string
	Port int
	User string
	Pass string
}

func DefaultConfig() Config {
	return Config{
		RequireEmailVerification: false,
		InviteTTL:           7 * 24 * time.Hour,
		VerificationCodeTTL: 15 * time.Minute,
		SessionTTL:          30 * 24 * time.Hour,
		TokenTTL:            1 * time.Hour,
		BcryptCost:          12,
		TokenLength:         32,
	}
}
