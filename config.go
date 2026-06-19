package goauth

import (
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

type Config struct {
	AppName     string
	AdminEmails []string
	SecretKey   string

	Database  DatabaseConfig
	Email     *EmailConfig
	RateLimit *port.RateLimitConfig

	InviteOnly          bool
	InviteTTL           time.Duration
	VerificationCodeTTL time.Duration
	SessionTTL          time.Duration
	TokenTTL            time.Duration
	BcryptCost          int
	TokenLength         int

	EmailTemplates EmailTemplates
}

type DatabaseConfig struct {
	Driver string // "postgres"
	DSN    string
	Schema string // path to .sql file or "embedded"
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

type EmailTemplates struct {
	VerifyEmail   string // path to HTML template, or "" for default
	PasswordReset string
	InviteEmail   string
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
