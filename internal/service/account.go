package service

import (
	"context"
	"fmt"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// AttachAccountSessions supplies authoritative session identity for self-service.
func (s *AuthService) AttachAccountSessions(sessions port.SessionIdentityReader) {
	s.accountSessions = sessions
}

// ValidateAccountActor checks current identity and ordinary account access for
// a self-service operation. Actor IDs must originate in trusted authentication.
// This is a live guard, not a cached assertion or an atomic check/write boundary.
func (s *AuthService) ValidateAccountActor(ctx context.Context, actor api.Actor) (*domain.User, *domain.Session, error) {
	return s.accountActor(ctx, actor, true)
}

// ValidateAccountIdentity retains verification-pending identity for logout and
// verification resend. It still rejects expired, revoked and banned identities.
func (s *AuthService) ValidateAccountIdentity(ctx context.Context, actor api.Actor) (*domain.User, *domain.Session, error) {
	return s.accountActor(ctx, actor, false)
}

func (s *AuthService) accountActor(ctx context.Context, actor api.Actor, requireVerified bool) (*domain.User, *domain.Session, error) {
	if actor.UserID == "" || actor.SessionID == "" {
		return nil, nil, domain.ErrForbidden
	}
	if s.accountSessions == nil {
		return nil, nil, domain.ErrForbidden
	}
	session, err := s.accountSessions.GetByID(ctx, actor.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("account actor session: %w", err)
	}
	if session == nil || session.UserID != actor.UserID {
		return nil, nil, domain.ErrForbidden
	}
	if err := s.sessionSvc.checkSession(session); err != nil {
		return nil, nil, err
	}
	user, err := s.users.GetByID(ctx, actor.UserID)
	if err != nil {
		return nil, nil, fmt.Errorf("account actor user: %w", err)
	}
	if user == nil || user.IsBanned {
		return nil, nil, domain.ErrForbidden
	}
	if requireVerified {
		if err := s.sessionSvc.checkUserAccess(user); err != nil {
			return nil, nil, err
		}
	}
	return user, session, nil
}
