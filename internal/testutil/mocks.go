package testutil

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// ─── mockUserRepo ──────────────────────────────────────────────────

type MockUserRepo struct {
	mu    sync.Mutex
	users map[string]*domain.User
}

func NewMockUserRepo() *MockUserRepo {
	return &MockUserRepo{users: make(map[string]*domain.User)}
}

func (m *MockUserRepo) Create(_ context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.users[user.Email] = user
	return nil
}

func (m *MockUserRepo) GetByID(_ context.Context, id string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *MockUserRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[email]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *MockUserRepo) Update(_ context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.users[user.Email] = user
	return nil
}

func (m *MockUserRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	if u != nil {
		delete(m.users, u.Email)
	}
	delete(m.users, id)
	return nil
}

func (m *MockUserRepo) List(_ context.Context, _ port.UserFilter) ([]domain.User, int, error) {
	return nil, 0, nil
}

func (m *MockUserRepo) SetBanStatus(_ context.Context, userID string, isBanned bool, bannedAt *time.Time, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return nil
	}
	u.IsBanned = isBanned
	u.BannedAt = bannedAt
	return nil
}

func (m *MockUserRepo) SetPasswordAndVerify(_ context.Context, userID string, passwordHash string, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return nil
	}
	now := time.Now().UTC()
	u.PasswordHash = &passwordHash
	u.IsVerified = true
	u.VerifiedAt = &now
	u.UpdatedAt = now
	return nil
}

// ─── mockSessionRepo ───────────────────────────────────────────────

type MockSessionRepo struct {
	mu       sync.Mutex
	sessions map[string]*domain.Session
	byID     map[string]*domain.Session
}

func NewMockSessionRepo() *MockSessionRepo {
	return &MockSessionRepo{
		sessions: make(map[string]*domain.Session),
		byID:     make(map[string]*domain.Session),
	}
}

func (m *MockSessionRepo) Create(_ context.Context, s *domain.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.TokenHash] = s
	m.byID[s.ID] = s
	return nil
}

func (m *MockSessionRepo) GetByTokenHash(_ context.Context, hash string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *MockSessionRepo) ListByUserID(_ context.Context, userID string) ([]domain.Session, error) {
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

func (m *MockSessionRepo) Delete(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenHash]
	if ok {
		delete(m.sessions, tokenHash)
		delete(m.byID, s.ID)
	}
	return nil
}

func (m *MockSessionRepo) DeleteByID(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if ok {
		delete(m.byID, id)
		delete(m.sessions, s.TokenHash)
	}
	return nil
}

func (m *MockSessionRepo) DeleteAllForUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.byID {
		if s.UserID == userID {
			delete(m.byID, k)
			delete(m.sessions, s.TokenHash)
		}
	}
	return nil
}

func (m *MockSessionRepo) DeleteAllForUserExcept(_ context.Context, userID string, exceptSessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.byID {
		if s.UserID == userID && s.ID != exceptSessionID {
			delete(m.byID, k)
			delete(m.sessions, s.TokenHash)
		}
	}
	return nil
}

func (m *MockSessionRepo) DeleteExpired(_ context.Context) error {
	return nil
}

func (m *MockSessionRepo) UpdateLastActiveAt(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[tokenHash]; ok {
		s.LastActiveAt = time.Now().UTC()
	}
	return nil
}

// ─── mockTokenRepo ─────────────────────────────────────────────────

type MockTokenRepo struct {
	mu     sync.Mutex
	tokens map[string]*domain.VerificationToken
}

func NewMockTokenRepo() *MockTokenRepo {
	return &MockTokenRepo{tokens: make(map[string]*domain.VerificationToken)}
}

func (m *MockTokenRepo) Create(_ context.Context, t *domain.VerificationToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.ID] = t
	m.tokens[t.TokenHash] = t
	return nil
}

func (m *MockTokenRepo) GetByHash(_ context.Context, hash string) (*domain.VerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[hash]
	if !ok {
		return nil, nil
	}
	return t, nil
}

func (m *MockTokenRepo) MarkUsed(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if ok {
		now := time.Now().UTC()
		t.UsedAt = &now
	}
	return nil
}

func (m *MockTokenRepo) DeleteExpired(_ context.Context) error {
	return nil
}

func (m *MockTokenRepo) DeleteUnusedByUserAndType(_ context.Context, userID string, tokenType domain.TokenType) error {
	return nil
}

// ─── mockHasher ─────────────────────────────────────────────────────

type MockHasher struct{}

func (m *MockHasher) Hash(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]), nil
}

func (m *MockHasher) Compare(password, hash string) error {
	sum := sha256.Sum256([]byte(password))
	if hex.EncodeToString(sum[:]) != hash {
		return domain.ErrInvalidCredentials
	}
	return nil
}

// ─── mockTokenGen ───────────────────────────────────────────────────

type MockTokenGen struct {
	Length int
}

func (m *MockTokenGen) Generate() (string, error) {
	b := make([]byte, m.Length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ─── mockInviteRepo ────────────────────────────────────────────────

type MockInviteRepo struct {
	mu      sync.Mutex
	invites map[string]*domain.Invite
}

func NewMockInviteRepo() *MockInviteRepo {
	return &MockInviteRepo{invites: make(map[string]*domain.Invite)}
}

func (m *MockInviteRepo) Create(_ context.Context, invite *domain.Invite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[invite.ID] = invite
	m.invites[invite.Code] = invite
	m.invites["email:"+invite.Email] = invite
	return nil
}

func (m *MockInviteRepo) GetByID(_ context.Context, id string) (*domain.Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *MockInviteRepo) GetByCode(_ context.Context, code string) (*domain.Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[code]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *MockInviteRepo) GetByEmail(_ context.Context, email string) (*domain.Invite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites["email:"+email]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *MockInviteRepo) List(_ context.Context, filter port.InviteFilter) ([]domain.Invite, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []domain.Invite
	for _, inv := range m.invites {
		if inv.ID != "" && inv.Code != "" {
			if filter.Search != nil && *filter.Search != "" {
				if !strings.Contains(inv.Email, *filter.Search) {
					continue
				}
			}
			if filter.Status != nil && *filter.Status != "" {
				if string(inv.Status) != *filter.Status {
					continue
				}
			}
			result = append(result, *inv)
		}
	}
	return result, len(result), nil
}

func (m *MockInviteRepo) Update(_ context.Context, invite *domain.Invite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[invite.ID] = invite
	m.invites[invite.Code] = invite
	m.invites["email:"+invite.Email] = invite
	return nil
}

func (m *MockInviteRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if inv, ok := m.invites[id]; ok {
		delete(m.invites, id)
		delete(m.invites, inv.Code)
		delete(m.invites, "email:"+inv.Email)
	}
	return nil
}
