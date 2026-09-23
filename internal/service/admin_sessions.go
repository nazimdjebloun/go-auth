package service

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// RevokeUserSessionsInput identifies the user whose sessions to revoke.
type RevokeUserSessionsInput struct {
	UserID  string
	ActorID string
}

// RevokeUserSessions revokes every session for a user.
func (s *AdminService) RevokeUserSessions(ctx context.Context, input RevokeUserSessionsInput) error {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return err
	}
	_, err := s.targetUser(ctx, input.UserID)
	if err != nil {
		return err
	}

	if err := s.sessionSvc.RevokeAll(ctx, input.UserID); err != nil {
		s.log.Error("failed to revoke sessions", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("user sessions revoked by admin", "user_id", input.UserID)
	return nil
}

// AdminListSessionsInput scopes an admin-wide session search — every filter
// beyond ActorID is optional and composable (e.g. UserID + IP together).
type AdminListSessionsInput struct {
	ActorID          string
	UserID           *string
	IP               *string
	Search           *string
	CreatedAfter     *time.Time
	CreatedBefore    *time.Time
	ExpiresAfter     *time.Time
	ExpiresBefore    *time.Time
	LastActiveAfter  *time.Time
	LastActiveBefore *time.Time
	OrderBy          port.SessionSortField
	OrderDirection   port.SortDirection
	Offset           int
	Limit            int
}

// AdminListSessionsResult contains sessions and the matching total.
type AdminListSessionsResult struct {
	Sessions []domain.Session `json:"sessions"`
	Limit    int              `json:"limit"`
	Offset   int              `json:"offset"`
}

// ListSessions returns active sessions across every user — the
// incident-response view ("who's logged in right now", "every session from
// this IP"), as opposed to ListUserSessions which is scoped to one user.
func (s *AdminService) ListSessions(ctx context.Context, input AdminListSessionsInput) (*AdminListSessionsResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}

	sessions, err := s.sessions.ListAll(ctx, s.sessionFilterFromInput(input, limit))
	if err != nil {
		s.log.Error("failed to list sessions", "err", err)
		return nil, domain.ErrInternal
	}

	return &AdminListSessionsResult{Sessions: sessions, Limit: limit, Offset: input.Offset}, nil
}

func (s *AdminService) sessionFilterFromInput(input AdminListSessionsInput, limit int) port.SessionFilter {
	return port.SessionFilter{
		UserID:           input.UserID,
		IP:               input.IP,
		Search:           input.Search,
		CreatedAfter:     input.CreatedAfter,
		CreatedBefore:    input.CreatedBefore,
		ExpiresAfter:     input.ExpiresAfter,
		ExpiresBefore:    input.ExpiresBefore,
		LastActiveAfter:  input.LastActiveAfter,
		LastActiveBefore: input.LastActiveBefore,
		OrderBy:          input.OrderBy,
		OrderDirection:   input.OrderDirection,
		Offset:           input.Offset,
		Limit:            limit,
	}
}

// CountSessions returns how many sessions match the input's filters
// (pagination ignored).
func (s *AdminService) CountSessions(ctx context.Context, input AdminListSessionsInput) (int, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return 0, err
	}
	f := s.sessionFilterFromInput(input, 0)
	f.Offset, f.Limit = 0, 0
	n, err := s.sessions.CountAll(ctx, f)
	if err != nil {
		s.log.Error("failed to count sessions", "err", err)
		return 0, domain.ErrInternal
	}
	return n, nil
}

// ListUserSessions returns a page of sessions for a user.
func (s *AdminService) ListUserSessions(ctx context.Context, input AdminListUserSessionsInput) ([]domain.Session, int, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, 0, err
	}
	_, err := s.targetUser(ctx, input.UserID)
	if err != nil {
		return nil, 0, err
	}

	sessions, total, err := s.sessions.ListByUserID(ctx, input.UserID, input.Offset, input.Limit)
	if err != nil {
		s.log.Error("failed to list user sessions", "err", err, "user_id", input.UserID)
		return nil, 0, domain.ErrInternal
	}

	return sessions, total, nil
}

// RevokeUserSessionInput identifies one user session to revoke.
type RevokeUserSessionInput struct {
	UserID    string
	SessionID string
	ActorID   string
}

// RevokeUserSession revokes one session for a user.
func (s *AdminService) RevokeUserSession(ctx context.Context, input RevokeUserSessionInput) error {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return err
	}
	_, err := s.targetUser(ctx, input.UserID)
	if err != nil {
		return err
	}

	revoked, err := s.sessionSvc.RevokeByIDForUser(ctx, input.SessionID, input.UserID)
	if err != nil {
		s.log.Error("failed to revoke session", "err", err, "user_id", input.UserID, "session_id", input.SessionID)
		return domain.ErrInternal
	}
	if !revoked {
		return domain.NewError("session_not_found", "Session not found")
	}

	s.log.Info("user session revoked by admin", "user_id", input.UserID, "session_id", input.SessionID)
	return nil
}
