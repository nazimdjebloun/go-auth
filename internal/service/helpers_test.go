package service

import (
	"context"
	"errors"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
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
		OTPPepper:                testOTPPepper(),
	}
}

// testOTPPepper is the HMAC pepper unit tests store low-entropy codes with.
// It mirrors what Auth.New derives via keyring (a 32-byte subkey under a
// dedicated purpose string), fixed so tests can recompute the same MAC when
// seeding rows directly.
func testOTPPepper() []byte {
	return []byte("test-otp-pepper-32-bytes-long!!!")
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

// newTestAdminService also seeds and returns an admin actor's ID — every
// AdminService method requires one now, so tests use this as the caller.
func newTestAdminService(users *testutil.MockUserRepo, sessions *testutil.MockSessionRepo, hasher *testutil.MockHasher) (*AdminService, string) {
	svc, actorID, _ := newTestAdminServiceWithAudit(users, sessions, testutil.NewMockAuditLogRepo(), hasher)
	return svc, actorID
}

// newTestAdminServiceWithAudit is newTestAdminService plus an explicit,
// caller-supplied audit log mock — for GetStats/GetRegistrationTrend/
// GetLoginActivity tests that need to seed audit rows into the exact
// instance the service under test reads from.
func newTestAdminServiceWithAudit(users *testutil.MockUserRepo, sessions *testutil.MockSessionRepo, auditLogs *testutil.MockAuditLogRepo, hasher *testutil.MockHasher) (*AdminService, string, *testutil.MockAuditLogRepo) {
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	providers := testutil.NewMockProviderAccountRepo()
	actor := &domain.User{ID: "actor-admin", Email: "actor-admin@example.com", Role: domain.RoleAdmin}
	users.Create(context.Background(), actor)
	svc := NewAdminService(users, sessions, providers, auditLogs, hasher, cfg, sessSvc)
	// Production wiring always attaches the coordinator; do the same here
	// so DeleteUser exercises the real transactional path.
	svc.AttachAccountDeletion(NewAccountDeletion(&testutil.MockTxManager{}, nil, sessions, users))
	return svc, actor.ID, auditLogs
}
