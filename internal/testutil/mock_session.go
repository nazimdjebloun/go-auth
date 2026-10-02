package testutil

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// MockSessionRepo is an in-memory session repository for tests.
type MockSessionRepo struct {
	mu            sync.Mutex
	sessions      map[string]*domain.Session
	byID          map[string]*domain.Session
	byRefreshHash map[string]*domain.Session
	// ClearActiveOrgCalls records session IDs passed to ClearActiveOrg.
	ClearActiveOrgCalls []string

	// Users backs GetByTokenHashWithUser, which the real repo answers with a
	// JOIN. Leave it nil for tests that never take the ValidateWithUser path
	// (that method then reports no match, exactly as the inner join does for
	// a session whose user row is gone); set it to resolve users properly.
	Users *MockUserRepo
}

// NewMockSessionRepo returns an in-memory session repository.
func NewMockSessionRepo() *MockSessionRepo {
	return &MockSessionRepo{
		sessions:      make(map[string]*domain.Session),
		byID:          make(map[string]*domain.Session),
		byRefreshHash: make(map[string]*domain.Session),
	}
}

// Create stores a session.
func (m *MockSessionRepo) Create(ctx context.Context, s *domain.Session) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.TokenHash] = s
	m.byID[s.ID] = s
	if s.RefreshTokenHash != "" {
		m.byRefreshHash[s.RefreshTokenHash] = s
	}
	return nil
}

// GetByTokenHash returns a session by access-token hash.
func (m *MockSessionRepo) GetByTokenHash(ctx context.Context, hash string) (*domain.Session, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return nil, nil
	}
	return s, nil
}

// GetByTokenHashWithUser mirrors the real repo's inner join: no session, or a
// session whose user cannot be resolved, both come back as (nil, nil, nil).
func (m *MockSessionRepo) GetByTokenHashWithUser(ctx context.Context, hash string) (*domain.Session, *domain.User, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	s, ok := m.sessions[hash]
	users := m.Users
	m.mu.Unlock()
	if !ok || users == nil {
		return nil, nil, nil
	}
	u, err := users.GetByID(ctx, s.UserID)
	if err != nil || u == nil {
		return nil, nil, err
	}
	return s, u, nil
}

// GetByRefreshHash returns a session by refresh-token hash.
func (m *MockSessionRepo) GetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byRefreshHash[hash]
	if !ok {
		return nil, nil
	}
	return s, nil
}

// GetByPreviousRefreshHash returns a session by its previous refresh-token hash.
func (m *MockSessionRepo) GetByPreviousRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.byID {
		if s.PreviousRefreshHash == hash {
			return s, nil
		}
	}
	return nil, nil
}

// LockAndGetByRefreshHash returns a session by refresh-token hash.
func (m *MockSessionRepo) LockAndGetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	recordMockTx(ctx, m)
	return m.GetByRefreshHash(ctx, hash)
}

// ListByUserID returns a page of sessions for a user.
func (m *MockSessionRepo) ListByUserID(ctx context.Context, userID string, offset, limit int) ([]domain.Session, int, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []domain.Session
	for _, s := range m.byID {
		if s.UserID == userID && !s.IsRevoked {
			res = append(res, *s)
		}
	}
	total := len(res)
	if offset > 0 && offset < total {
		res = res[offset:]
	} else if offset >= total {
		res = []domain.Session{}
	}
	if limit > 0 && limit < len(res) {
		res = res[:limit]
	}
	return res, total, nil
}

// ListAllByUserID returns all sessions for a user.
func (m *MockSessionRepo) ListAllByUserID(ctx context.Context, userID string) ([]domain.Session, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []domain.Session
	for _, s := range m.byID {
		if s.UserID == userID && !s.IsRevoked {
			res = append(res, *s)
		}
	}
	return res, nil
}

// CountAll returns the number of matching sessions.
func (m *MockSessionRepo) CountAll(ctx context.Context, filter port.SessionFilter) (int, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.byID {
		if !s.IsRevoked && sessionMatchesFilter(s, filter) {
			n++
		}
	}
	return n, nil
}

// ListAll returns matching sessions.
func (m *MockSessionRepo) ListAll(ctx context.Context, filter port.SessionFilter) ([]domain.Session, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []domain.Session
	for _, s := range m.byID {
		if !s.IsRevoked && sessionMatchesFilter(s, filter) {
			res = append(res, *s)
		}
	}

	sort.SliceStable(res, func(i, j int) bool {
		var ci, cj time.Time
		switch filter.OrderBy {
		case "expires_at":
			ci, cj = res[i].ExpiresAt, res[j].ExpiresAt
		case "last_active_at":
			ci, cj = res[i].LastActiveAt, res[j].LastActiveAt
		default:
			ci, cj = res[i].CreatedAt, res[j].CreatedAt
		}
		if filter.OrderDirection == api.SortAscending {
			return ci.Before(cj)
		}
		return ci.After(cj)
	})

	total := len(res)
	if filter.Offset > 0 && filter.Offset < total {
		res = res[filter.Offset:]
	} else if filter.Offset >= total {
		res = []domain.Session{}
	}
	if filter.Limit > 0 && filter.Limit < len(res) {
		res = res[:filter.Limit]
	}
	return res, nil
}

func sessionMatchesFilter(s *domain.Session, filter port.SessionFilter) bool {
	if filter.UserID != nil && s.UserID != *filter.UserID {
		return false
	}
	if filter.IP != nil && s.IP != *filter.IP {
		return false
	}
	if filter.Search != nil && *filter.Search != "" {
		q := strings.ToLower(*filter.Search)
		if !strings.Contains(strings.ToLower(s.IP), q) && !strings.Contains(strings.ToLower(s.UserAgent), q) {
			return false
		}
	}
	if filter.CreatedAfter != nil && s.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}
	if filter.CreatedBefore != nil && s.CreatedAt.After(*filter.CreatedBefore) {
		return false
	}
	if filter.ExpiresAfter != nil && s.ExpiresAt.Before(*filter.ExpiresAfter) {
		return false
	}
	if filter.ExpiresBefore != nil && s.ExpiresAt.After(*filter.ExpiresBefore) {
		return false
	}
	if filter.LastActiveAfter != nil && s.LastActiveAt.Before(*filter.LastActiveAfter) {
		return false
	}
	if filter.LastActiveBefore != nil && s.LastActiveAt.After(*filter.LastActiveBefore) {
		return false
	}
	return true
}

// Delete removes a session by access-token hash.
func (m *MockSessionRepo) Delete(ctx context.Context, tokenHash string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenHash]
	if ok {
		delete(m.sessions, tokenHash)
		delete(m.byID, s.ID)
		if s.RefreshTokenHash != "" {
			delete(m.byRefreshHash, s.RefreshTokenHash)
		}
	}
	return nil
}

// DeleteByID removes a session by ID.
func (m *MockSessionRepo) DeleteByID(ctx context.Context, id string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if ok {
		delete(m.byID, id)
		delete(m.sessions, s.TokenHash)
		if s.RefreshTokenHash != "" {
			delete(m.byRefreshHash, s.RefreshTokenHash)
		}
	}
	return nil
}

// RevokeByIDForUser removes one of a user's sessions.
func (m *MockSessionRepo) RevokeByIDForUser(ctx context.Context, id, userID string) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if ok && s.UserID == userID {
		delete(m.byID, id)
		delete(m.sessions, s.TokenHash)
		if s.RefreshTokenHash != "" {
			delete(m.byRefreshHash, s.RefreshTokenHash)
		}
		return true, nil
	}
	return false, nil
}

// RevokeManyForUser removes multiple sessions for a user.
func (m *MockSessionRepo) RevokeManyForUser(ctx context.Context, ids []string, userID string) (int, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	revoked := 0
	for _, id := range ids {
		s, ok := m.byID[id]
		if ok && s.UserID == userID {
			delete(m.byID, id)
			delete(m.sessions, s.TokenHash)
			if s.RefreshTokenHash != "" {
				delete(m.byRefreshHash, s.RefreshTokenHash)
			}
			revoked++
		}
	}
	return revoked, nil
}

// DeleteAllForUser removes every session for a user.
func (m *MockSessionRepo) DeleteAllForUser(ctx context.Context, userID string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.byID {
		if s.UserID == userID {
			delete(m.byID, k)
			delete(m.sessions, s.TokenHash)
			if s.RefreshTokenHash != "" {
				delete(m.byRefreshHash, s.RefreshTokenHash)
			}
		}
	}
	return nil
}

// DeleteAllForUserExcept removes every user session except one.
func (m *MockSessionRepo) DeleteAllForUserExcept(ctx context.Context, userID string, exceptSessionID string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.byID {
		if s.UserID == userID && s.ID != exceptSessionID {
			delete(m.byID, k)
			delete(m.sessions, s.TokenHash)
			if s.RefreshTokenHash != "" {
				delete(m.byRefreshHash, s.RefreshTokenHash)
			}
		}
	}
	return nil
}

// DeleteExpired removes expired sessions.
func (m *MockSessionRepo) DeleteExpired(ctx context.Context) error {
	recordMockTx(ctx, m)
	return nil
}

// UpdateLastActiveAt records activity for a session.
func (m *MockSessionRepo) UpdateLastActiveAt(ctx context.Context, tokenHash string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[tokenHash]; ok {
		s.LastActiveAt = time.Now().UTC()
	}
	return nil
}

// UpdateRefreshToken rotates a session's tokens.
func (m *MockSessionRepo) UpdateRefreshToken(ctx context.Context, input port.UpdateRefreshInput) (*domain.Session, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()

	// Collision guard
	if input.NewRefreshHash == input.OldRefreshHash {
		return nil, domain.NewError("internal_error", "Refresh token collision: new hash equals old hash")
	}
	if input.NewRefreshHash == input.NewTokenHash {
		return nil, domain.NewError("internal_error", "Token hash collision: refresh hash equals access token hash")
	}

	now := input.RotatedAt
	s, ok := m.byRefreshHash[input.OldRefreshHash]
	if ok {
		if s.IsRevoked {
			return nil, domain.ErrSessionRevoked
		}
		if now.After(s.RefreshExpiresAt) {
			return nil, domain.ErrRefreshExpired
		}
		if input.MaxLifetime > 0 && now.After(s.CreatedAt.Add(input.MaxLifetime)) {
			return nil, domain.ErrMaxLifetimeExceeded
		}

		// Rotate
		delete(m.byRefreshHash, s.RefreshTokenHash)
		delete(m.sessions, s.TokenHash)
		s.TokenHash = input.NewTokenHash
		s.RefreshTokenHash = input.NewRefreshHash
		s.PreviousRefreshHash = input.OldRefreshHash
		s.ExpiresAt = input.NewExpiresAt
		s.RefreshRotatedAt = &now
		s.LastActiveAt = now
		m.sessions[input.NewTokenHash] = s
		m.byRefreshHash[input.NewRefreshHash] = s
		return s, nil
	}

	// Check previous hash
	for _, prev := range m.byID {
		if prev.PreviousRefreshHash == input.OldRefreshHash {
			if prev.RefreshRotatedAt != nil && now.Sub(*prev.RefreshRotatedAt) < input.GraceWindow {
				return nil, domain.ErrTokenAlreadyRotated
			}
			delete(m.byID, prev.ID)
			delete(m.sessions, prev.TokenHash)
			delete(m.byRefreshHash, prev.RefreshTokenHash)
			return nil, &port.ErrRefreshTokenReused{UserID: prev.UserID, SessionID: prev.ID}
		}
	}

	return nil, domain.ErrInvalidRefreshToken
}

// UpdateActiveOrgRoleForUser changes the active organization role in matching sessions.
func (m *MockSessionRepo) UpdateActiveOrgRoleForUser(ctx context.Context, _, _ string, _ domain.OrgRole) error {
	recordMockTx(ctx, m)
	return nil
}

// ClearActiveOrgForUser clears an organization from a user's sessions.
func (m *MockSessionRepo) ClearActiveOrgForUser(ctx context.Context, _, _ string) error {
	recordMockTx(ctx, m)
	return nil
}

// ClearActiveOrg clears the active organization from a session.
func (m *MockSessionRepo) ClearActiveOrg(ctx context.Context, sessionID string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ClearActiveOrgCalls = append(m.ClearActiveOrgCalls, sessionID)
	return nil
}

// ClearActiveOrgForAllMembers clears an organization from every session.
func (m *MockSessionRepo) ClearActiveOrgForAllMembers(ctx context.Context, _ string) error {
	recordMockTx(ctx, m)
	return nil
}

// SetActiveOrg sets a session's active organization.
func (m *MockSessionRepo) SetActiveOrg(ctx context.Context, _, _ string, _ domain.OrgRole) error {
	recordMockTx(ctx, m)
	return nil
}
