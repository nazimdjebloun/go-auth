package service

import (
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

func defaultTestConfig() Config {
	return Config{
		AppName:                 "TestApp",
		RequireEmailVerification: false,
		EnableEmailPassword:      true,
		EnableOAuth:              true,
		EnableInvite:             true,
		InviteTTL:               7 * 24 * time.Hour,
		VerificationCodeTTL:     15 * time.Minute,
		SessionTTL:              30 * 24 * time.Hour,
		TokenTTL:                1 * time.Hour,
		BaseURL:                 "http://localhost:3000",
		URLValidator:            &port.URLValidator{AllowHTTP: true},
	}
}

func newTestSessionService(repo port.SessionRepository, gen port.TokenGenerator) *SessionService {
	return NewSessionService(repo, gen, DefaultSessionConfig())
}
