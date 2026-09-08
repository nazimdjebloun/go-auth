package testutil

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type MockOrgRepo struct {
	mu      sync.Mutex
	orgs    map[string]*domain.Organization
	members map[string]*domain.OrgMember // key: "orgID:userID"
	// users resolves a member's User for ListMembers (name/email search and
	// populating OrgMemberDetail.User) — optional, set via SetUsers. Tests
	// that don't call SetUsers get the pre-existing behavior (no User
	// populated, no search match).
	users port.UserRepository
	// GetMembershipErr, when non-nil, is returned by GetMembership before
	// any lookup — lets tests exercise repository-failure paths.
	GetMembershipErr error
}

func NewMockOrgRepo() *MockOrgRepo {
	return &MockOrgRepo{
		orgs:    make(map[string]*domain.Organization),
		members: make(map[string]*domain.OrgMember),
	}
}

// SetUsers wires a user repository into the mock so ListMembers can
// populate OrgMemberDetail.User and evaluate OrgMemberFilter.Search against
// real name/email values, matching what the real sqlstore join does.
func (m *MockOrgRepo) SetUsers(users port.UserRepository) {
	m.users = users
}

func (m *MockOrgRepo) Create(_ context.Context, org *domain.Organization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orgs[org.ID] = org
	m.orgs[org.Slug] = org
	return nil
}

func (m *MockOrgRepo) GetByID(_ context.Context, id string) (*domain.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	org, ok := m.orgs[id]
	if !ok {
		return nil, nil
	}
	return org, nil
}

func (m *MockOrgRepo) GetBySlug(_ context.Context, slug string) (*domain.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	org, ok := m.orgs[slug]
	if !ok {
		return nil, nil
	}
	return org, nil
}

func (m *MockOrgRepo) Update(_ context.Context, org *domain.Organization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orgs[org.ID] = org
	return nil
}

func (m *MockOrgRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.orgs, id)
	return nil
}

func (m *MockOrgRepo) AddMember(_ context.Context, member *domain.OrgMember) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := member.OrgID + ":" + member.UserID
	m.members[key] = member
	return nil
}

func (m *MockOrgRepo) RemoveMember(_ context.Context, orgID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID + ":" + userID
	delete(m.members, key)
	return nil
}

func (m *MockOrgRepo) UpdateMemberRole(_ context.Context, orgID, userID string, role domain.OrgRole) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID + ":" + userID
	if mem, ok := m.members[key]; ok {
		mem.Role = role
	}
	return nil
}

func (m *MockOrgRepo) GetMembership(_ context.Context, orgID, userID string) (*domain.OrgMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.GetMembershipErr != nil {
		return nil, m.GetMembershipErr
	}
	key := orgID + ":" + userID
	mem, ok := m.members[key]
	if !ok {
		return nil, nil
	}
	return mem, nil
}

func (m *MockOrgRepo) CountMembers(ctx context.Context, orgID string, filter port.OrgMemberFilter) (int, error) {
	f := filter
	f.Limit, f.Offset = 0, 0
	items, err := m.ListMembers(ctx, orgID, f)
	return len(items), err
}

func (m *MockOrgRepo) ListMembers(ctx context.Context, orgID string, filter port.OrgMemberFilter) ([]domain.OrgMemberDetail, error) {
	m.mu.Lock()
	var all []domain.OrgMemberDetail
	for _, mem := range m.members {
		if mem.OrgID != orgID {
			continue
		}
		md := domain.OrgMemberDetail{OrgMember: *mem}
		if m.users != nil {
			if u, err := m.users.GetByID(ctx, mem.UserID); err == nil && u != nil {
				md.User = u
			}
		}
		all = append(all, md)
	}
	m.mu.Unlock()

	if filter.Role != nil {
		filtered := all[:0:0]
		for _, md := range all {
			if md.Role == *filter.Role {
				filtered = append(filtered, md)
			}
		}
		all = filtered
	}
	if filter.Search != nil && *filter.Search != "" {
		term := strings.ToLower(*filter.Search)
		filtered := all[:0:0]
		for _, md := range all {
			if md.User != nil && (strings.Contains(strings.ToLower(md.User.Name), term) || strings.Contains(strings.ToLower(md.User.Email), term)) {
				filtered = append(filtered, md)
			}
		}
		all = filtered
	}

	sort.SliceStable(all, func(i, j int) bool {
		var less bool
		switch filter.OrderBy {
		case "role":
			less = string(all[i].Role) < string(all[j].Role)
		case "name":
			ni, nj := "", ""
			if all[i].User != nil {
				ni = all[i].User.Name
			}
			if all[j].User != nil {
				nj = all[j].User.Name
			}
			less = ni < nj
		case "email":
			ei, ej := "", ""
			if all[i].User != nil {
				ei = all[i].User.Email
			}
			if all[j].User != nil {
				ej = all[j].User.Email
			}
			less = ei < ej
		default:
			less = all[i].JoinedAt.Before(all[j].JoinedAt)
		}
		if strings.EqualFold(filter.OrderDirection, "asc") {
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
		page = []domain.OrgMemberDetail{}
	}
	return page, nil
}

func (m *MockOrgRepo) CountUserOrgs(ctx context.Context, userID string, filter port.UserOrgFilter) (int, error) {
	f := filter
	f.Limit, f.Offset = 0, 0
	items, err := m.ListUserOrgs(ctx, userID, f)
	return len(items), err
}

func (m *MockOrgRepo) ListUserOrgs(_ context.Context, userID string, filter port.UserOrgFilter) ([]domain.Organization, error) {
	m.mu.Lock()
	var all []domain.Organization
	for _, mem := range m.members {
		if mem.UserID != userID {
			continue
		}
		if org, ok := m.orgs[mem.OrgID]; ok {
			all = append(all, *org)
		}
	}
	m.mu.Unlock()

	if filter.Search != nil && *filter.Search != "" {
		term := strings.ToLower(*filter.Search)
		filtered := all[:0:0]
		for _, o := range all {
			if strings.Contains(strings.ToLower(o.Name), term) || strings.Contains(strings.ToLower(o.Slug), term) {
				filtered = append(filtered, o)
			}
		}
		all = filtered
	}

	sort.SliceStable(all, func(i, j int) bool {
		var less bool
		switch filter.OrderBy {
		case "created_at":
			less = all[i].CreatedAt.Before(all[j].CreatedAt)
		case "member_count":
			less = all[i].MemberCount < all[j].MemberCount
		default:
			less = all[i].Name < all[j].Name
		}
		if strings.EqualFold(filter.OrderDirection, "asc") {
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
		page = []domain.Organization{}
	}
	return page, nil
}

func (m *MockOrgRepo) Count(ctx context.Context, filter port.OrgFilter) (int, error) {
	f := filter
	f.Limit, f.Offset = 0, 0
	items, err := m.List(ctx, f)
	return len(items), err
}

func (m *MockOrgRepo) List(_ context.Context, filter port.OrgFilter) ([]domain.Organization, error) {
	m.mu.Lock()
	seen := make(map[string]bool)
	var all []domain.Organization
	for _, org := range m.orgs {
		// m.orgs is keyed by both ID and Slug pointing at the same org, so
		// dedupe by ID before treating this as a real listing.
		if seen[org.ID] {
			continue
		}
		seen[org.ID] = true
		all = append(all, *org)
	}
	m.mu.Unlock()

	if filter.Search != nil && *filter.Search != "" {
		term := strings.ToLower(*filter.Search)
		filtered := all[:0:0]
		for _, o := range all {
			if strings.Contains(strings.ToLower(o.Name), term) || strings.Contains(strings.ToLower(o.Slug), term) {
				filtered = append(filtered, o)
			}
		}
		all = filtered
	}
	if filter.CreatedAfter != nil {
		filtered := all[:0:0]
		for _, o := range all {
			if o.CreatedAt.After(*filter.CreatedAfter) {
				filtered = append(filtered, o)
			}
		}
		all = filtered
	}
	if filter.CreatedBefore != nil {
		filtered := all[:0:0]
		for _, o := range all {
			if o.CreatedAt.Before(*filter.CreatedBefore) {
				filtered = append(filtered, o)
			}
		}
		all = filtered
	}

	sort.SliceStable(all, func(i, j int) bool {
		var less bool
		switch filter.OrderBy {
		case "created_at":
			less = all[i].CreatedAt.Before(all[j].CreatedAt)
		case "member_count":
			less = all[i].MemberCount < all[j].MemberCount
		default:
			less = all[i].Name < all[j].Name
		}
		if strings.EqualFold(filter.OrderDirection, "asc") {
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
		page = []domain.Organization{}
	}
	return page, nil
}

func (m *MockOrgRepo) IncrementUserOrgOwnerCount(_ context.Context, userID string, maxOrgs int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, mem := range m.members {
		if mem.UserID == userID && mem.Role == domain.OrgRoleOwner {
			count++
		}
	}
	if count >= maxOrgs {
		return domain.ErrOrgLimitReached
	}
	return nil
}

func (m *MockOrgRepo) DecrementUserOrgOwnerCount(_ context.Context, userID string) error {
	return nil
}

func (m *MockOrgRepo) IncrementOrgMemberCount(_ context.Context, orgID string, maxMembers int) error {
	return nil
}

func (m *MockOrgRepo) DecrementOrgMemberCount(_ context.Context, orgID string) error {
	return nil
}

func (m *MockOrgRepo) TryDecrementOrgOwnerCount(_ context.Context, orgID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, mem := range m.members {
		if mem.OrgID == orgID && mem.Role == domain.OrgRoleOwner {
			count++
		}
	}
	if count <= 1 {
		return domain.ErrCannotRemoveLastOwner
	}
	return nil
}

func (m *MockOrgRepo) IncrementOrgOwnerCount(_ context.Context, orgID string) error {
	return nil
}

func (m *MockOrgRepo) DecrementOwnerCountForOrgOwners(_ context.Context, orgID string) error {
	return nil
}
