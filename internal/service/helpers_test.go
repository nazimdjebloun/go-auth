package service

import (
	"errors"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// authErrCode extracts the Code of a *domain.AuthError for test assertions.
// Every service method here returns error, not *domain.AuthError directly
// (see PLANS/api-hardening-v1/07-error-unification.md), so tests that used
// to read err.Code need errors.As to get there. Returns "" for a nil error
// or one that isn't an AuthError — callers already assert err != nil (or
// err == nil) separately, so this only needs to make .Code reachable.
func authErrCode(err error) string {
	var ae *domain.AuthError
	errors.As(err, &ae)
	if ae == nil {
		return ""
	}
	return ae.Code
}

// authErrMessage is authErrCode's counterpart for the Message field.
func authErrMessage(err error) string {
	var ae *domain.AuthError
	errors.As(err, &ae)
	if ae == nil {
		return ""
	}
	return ae.Message
}

func defaultTestConfig() Config {
	return Config{
		CommonConfig: CommonConfig{
			AppName:    "TestApp",
			BaseURL:    "http://localhost:3000",
			SessionTTL: 30 * 24 * time.Hour,
			TokenTTL:   1 * time.Hour,
		},
		RequireEmailVerification: false,
		EnableEmailPassword:      true,
		EnableOAuth:              true,
		EnableInvite:             true,
		InviteTTL:                7 * 24 * time.Hour,
		VerificationCodeTTL:      15 * time.Minute,
		URLValidator:             &port.URLValidator{AllowHTTP: true},
	}
}

func newTestSessionService(repo port.SessionRepository, gen port.TokenGenerator) *SessionService {
	return NewSessionService(repo, gen, DefaultSessionConfig())
}

// newTestSessionServiceNoGrace is for tests that specifically exercise
// refresh-token reuse detection: DefaultSessionConfig's GraceWindow (5s)
// deliberately tolerates reusing the just-rotated token, which would mask
// the hard-revocation path these tests are checking.
func newTestSessionServiceNoGrace(repo port.SessionRepository, gen port.TokenGenerator) *SessionService {
	cfg := DefaultSessionConfig()
	cfg.GraceWindow = 0
	return NewSessionService(repo, gen, cfg)
}
