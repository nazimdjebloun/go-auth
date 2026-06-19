package goauth

import (
	"database/sql"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"
)

type Config struct {
	AppName     string
	AdminEmails []string

	Database  DatabaseConfig
	Mailer    Mailer
	Email     *EmailConfig
	RateLimit *ratelimit.Config

	InviteOnly          bool
	InviteTTL           time.Duration
	VerificationCodeTTL time.Duration
	SessionTTL          time.Duration
	TokenTTL            time.Duration
	BcryptCost          int
	TokenLength         int
}

type DatabaseConfig struct {
	DB     *sql.DB // existing database connection
	Driver string  // "postgres", "mysql", "sqlite3"
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
		InviteTTL:           7 * 24 * time.Hour,
		VerificationCodeTTL: 15 * time.Minute,
		SessionTTL:          30 * 24 * time.Hour,
		TokenTTL:            1 * time.Hour,
		BcryptCost:          12,
		TokenLength:         32,
	}
}
