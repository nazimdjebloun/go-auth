package testutil

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

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

func (m *MockInviteRepo) List(_ context.Context, filter port.InviteFilter) ([]domain.Invite, error) {
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

func (m *MockInviteRepo) Count(_ context.Context, filter port.InviteFilter) (int, error) {
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

func (m *MockInviteRepo) ClaimInvite(_ context.Context, code string, acceptedAt time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[code]
	if !ok || inv.Status != domain.InvitePending {
		return false, nil
	}
	inv.Status = domain.InviteAccepted
	inv.AcceptedAt = &acceptedAt
	return true, nil
}
