package goauth

import (
	"context"

	"github.com/nazimdjebloun/go-auth/domain"
)

// Register creates a new email/password account. input.IP and
// input.UserAgent, when set, are recorded on the resulting session and any
// audit event this produces — pass the caller's real values for a
// programmatic (non-HTTP) integration; the built-in HTTP handler already
// does this for you.
func (a *Auth) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	return a.authService.Register(ctx, input)
}

// Login authenticates an email/password account. input.IP and
// input.UserAgent, when set, are recorded on the resulting session and any
// audit event this produces.
func (a *Auth) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	return a.authService.Login(ctx, input)
}

// CompleteInviteRegistration finishes registration from an invite code.
// input.IP and input.UserAgent, when set, are recorded the same way as
// Register.
func (a *Auth) CompleteInviteRegistration(ctx context.Context, input CompleteInviteInput) (*CompleteInviteResult, error) {
	return a.inviteService.CompleteInviteRegistration(ctx, input)
}

// CheckSession validates a raw session token and returns whether it is valid.
// It checks the session exists, is not expired, and the associated user exists and is not banned.
func (a *Auth) CheckSession(ctx context.Context, tokenRaw string) bool {
	_, _, err := a.authService.ValidateSession(ctx, tokenRaw)
	return err == nil
}

// GetSession validates a raw session token and returns the associated user and session.
// Returns the user, session, and nil error on success.
// Returns nil, nil, error if the token is invalid, expired, or the user is banned.
func (a *Auth) GetSession(ctx context.Context, tokenRaw string) (*domain.User, *domain.Session, error) {
	user, session, err := a.authService.ValidateSession(ctx, tokenRaw)
	if err != nil {
		return nil, nil, err
	}
	return user, session, nil
}
