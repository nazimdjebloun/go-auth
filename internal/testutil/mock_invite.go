package testutil

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// MockInviteRepo stores platform invites in memory for tests.
type MockInviteRepo struct {
	mu      sync.Mutex
	invites map[string]*domain.Invite
}

// NewMockInviteRepo returns an empty invite repository.
func NewMockInviteRepo() *MockInviteRepo {
	return &MockInviteRepo{invites: make(map[string]*domain.Invite)}
}

// Create stores an invite under its ID, code, and email.
func (m *MockInviteRepo) Create(ctx context.Context, invite *domain.Invite) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[invite.ID] = invite
	m.invites[invite.Code] = invite
	m.invites["email:"+invite.Email] = invite
	return nil
}

// GetByID returns the invite with the given ID.
func (m *MockInviteRepo) GetByID(ctx context.Context, id string) (*domain.Invite, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

// GetByCode returns the invite with the given code.
func (m *MockInviteRepo) GetByCode(ctx context.Context, code string) (*domain.Invite, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[code]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

// GetByEmail returns the invite sent to the given email.
func (m *MockInviteRepo) GetByEmail(ctx context.Context, email string) (*domain.Invite, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites["email:"+email]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *MockInviteRepo) inviteMatches(inv *domain.Invite, filter port.InviteFilter) bool {
	if inv.ID == "" || inv.Code == "" {
		return false
	}
	if filter.Search != nil && *filter.Search != "" && !strings.Contains(inv.Email, *filter.Search) {
		return false
	}
	if filter.Status != nil && *filter.Status != "" && string(inv.Status) != *filter.Status {
		return false
	}
	return true
}

// List returns invites matching filter.
func (m *MockInviteRepo) List(ctx context.Context, filter port.InviteFilter) ([]domain.Invite, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []domain.Invite
	for _, inv := range m.invites {
		if m.inviteMatches(inv, filter) {
			result = append(result, *inv)
		}
	}
	return result, nil
}

// Count returns the number of invites matching filter.
func (m *MockInviteRepo) Count(ctx context.Context, filter port.InviteFilter) (int, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, inv := range m.invites {
		if m.inviteMatches(inv, filter) {
			n++
		}
	}
	return n, nil
}

// Update replaces the stored invite.
func (m *MockInviteRepo) Update(ctx context.Context, invite *domain.Invite) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[invite.ID] = invite
	m.invites[invite.Code] = invite
	m.invites["email:"+invite.Email] = invite
	return nil
}

// Delete removes the invite with the given ID.
func (m *MockInviteRepo) Delete(ctx context.Context, id string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	if inv, ok := m.invites[id]; ok {
		delete(m.invites, id)
		delete(m.invites, inv.Code)
		delete(m.invites, "email:"+inv.Email)
	}
	return nil
}

// ClaimInvite accepts a pending, unexpired invite.
func (m *MockInviteRepo) ClaimInvite(ctx context.Context, code string, acceptedAt time.Time) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[code]
	if !ok || inv.Status != domain.InvitePending || !inv.ExpiresAt.After(acceptedAt) {
		return false, nil
	}
	inv.Status = domain.InviteAccepted
	inv.AcceptedAt = &acceptedAt
	return true, nil
}
