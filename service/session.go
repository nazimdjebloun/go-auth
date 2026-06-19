package service

import (
	"context"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type SessionService struct {
	sessions port.SessionRepository
}

func NewSessionService(sessions port.SessionRepository) *SessionService {
	return &SessionService{sessions: sessions}
}

func (s *SessionService) ListSessions(ctx context.Context, userID string) ([]domain.Session, *domain.AuthError) {
	sessions, err := s.sessions.ListByUserID(ctx, userID)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to list sessions", 500)
	}
	return sessions, nil
}

func (s *SessionService) RevokeSession(ctx context.Context, sessionID, userID string) *domain.AuthError {
	sessions, err := s.sessions.ListByUserID(ctx, userID)
	if err != nil {
		return domain.NewError("internal_error", "Failed to list sessions", 500)
	}

	found := false
	for _, sess := range sessions {
		if sess.ID == sessionID {
			found = true
			break
		}
	}
	if !found {
		return domain.ErrSessionNotFound
	}

	if err := s.sessions.Revoke(ctx, sessionID); err != nil {
		return domain.NewError("internal_error", "Failed to revoke session", 500)
	}
	return nil
}

func (s *SessionService) RevokeAllSessions(ctx context.Context, userID string) *domain.AuthError {
	if err := s.sessions.RevokeAllForUser(ctx, userID); err != nil {
		return domain.NewError("internal_error", "Failed to revoke sessions", 500)
	}
	return nil
}
