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

// MockOrgInviteRepo is an in-memory organization invitation repository for tests.
type MockOrgInviteRepo struct {
	mu      sync.Mutex
	invites map[string]*domain.OrgInvite
}

// NewMockOrgInviteRepo returns an in-memory organization invitation repository.
func NewMockOrgInviteRepo() *MockOrgInviteRepo {
	return &MockOrgInviteRepo{invites: make(map[string]*domain.OrgInvite)}
}

// Create stores an organization invitation.
func (m *MockOrgInviteRepo) Create(ctx context.Context, invite *domain.OrgInvite) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[invite.ID] = invite
	m.invites["hash:"+invite.CodeHash] = invite
	return nil
}

// GetByID returns an organization invitation by ID.
func (m *MockOrgInviteRepo) GetByID(ctx context.Context, id string) (*domain.OrgInvite, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

// GetByCodeHash returns an organization invitation by code hash.
func (m *MockOrgInviteRepo) GetByCodeHash(ctx context.Context, codeHash string) (*domain.OrgInvite, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites["hash:"+codeHash]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

// CountByOrgID returns an organization's invitation count.
func (m *MockOrgInviteRepo) CountByOrgID(ctx context.Context, orgID string, filter port.OrgInviteFilter) (int, error) {
	recordMockTx(ctx, m)
	f := filter
	f.Limit, f.Offset = 0, 0
	items, err := m.ListByOrgID(ctx, orgID, f)
	return len(items), err
}

// ListByOrgID returns an organization's invitations.
func (m *MockOrgInviteRepo) ListByOrgID(ctx context.Context, orgID string, filter port.OrgInviteFilter) ([]domain.OrgInvite, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	var all []domain.OrgInvite
	seen := make(map[string]bool)
	for _, inv := range m.invites {
		if inv.OrgID == orgID && inv.ID != "" && !seen[inv.ID] {
			all = append(all, *inv)
			seen[inv.ID] = true
		}
	}
	m.mu.Unlock()

	if filter.Role != nil {
		filtered := all[:0:0]
		for _, inv := range all {
			if inv.Role == *filter.Role {
				filtered = append(filtered, inv)
			}
		}
		all = filtered
	}
	if filter.Status != nil {
		now := time.Now().UTC()
		filtered := all[:0:0]
		for _, inv := range all {
			expired := !inv.ExpiresAt.After(now)
			if (*filter.Status == "expired") == expired {
				filtered = append(filtered, inv)
			}
		}
		all = filtered
	}
	if filter.Search != nil && *filter.Search != "" {
		term := strings.ToLower(*filter.Search)
		filtered := all[:0:0]
		for _, inv := range all {
			if strings.Contains(strings.ToLower(inv.Email), term) {
				filtered = append(filtered, inv)
			}
		}
		all = filtered
	}

	sort.SliceStable(all, func(i, j int) bool {
		var less bool
		switch filter.OrderBy {
		case "expires_at":
			less = all[i].ExpiresAt.Before(all[j].ExpiresAt)
		case "email":
			less = all[i].Email < all[j].Email
		case "role":
			less = string(all[i].Role) < string(all[j].Role)
		default:
			less = all[i].CreatedAt.Before(all[j].CreatedAt)
		}
		if filter.OrderDirection == api.SortAscending {
			return less
		}
		return !less
	})

	total := len(all)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	end := total
	if filter.Limit > 0 {
		end = offset + filter.Limit
		if end > total {
			end = total
		}
	}
	page := all[offset:end]
	if page == nil {
		page = []domain.OrgInvite{}
	}
	return page, nil
}

// Update replaces an organization invitation.
func (m *MockOrgInviteRepo) Update(ctx context.Context, invite *domain.OrgInvite) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.invites[invite.ID]; ok {
		delete(m.invites, "hash:"+existing.CodeHash)
		existing.CodeHash = invite.CodeHash
		existing.ExpiresAt = invite.ExpiresAt
		m.invites["hash:"+existing.CodeHash] = existing
	}
	return nil
}

// Delete removes an organization invitation.
func (m *MockOrgInviteRepo) Delete(ctx context.Context, id string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	if inv, ok := m.invites[id]; ok {
		delete(m.invites, id)
		delete(m.invites, "hash:"+inv.CodeHash)
	}
	return nil
}

// ClaimInvite consumes a matching organization invitation.
func (m *MockOrgInviteRepo) ClaimInvite(ctx context.Context, id, codeHash string) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok || inv.CodeHash != codeHash || time.Now().UTC().After(inv.ExpiresAt) {
		return false, nil
	}
	delete(m.invites, id)
	delete(m.invites, "hash:"+inv.CodeHash)
	return true, nil
}
