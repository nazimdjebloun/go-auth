package testutil

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// MockOrgRepo is an in-memory organization repository for tests.
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

// NewMockOrgRepo returns an in-memory organization repository.
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

// Create stores an organization.
func (m *MockOrgRepo) Create(ctx context.Context, org *domain.Organization) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orgs[org.ID] = org
	m.orgs[org.Slug] = org
	return nil
}

// GetByID returns an organization by ID.
func (m *MockOrgRepo) GetByID(ctx context.Context, id string) (*domain.Organization, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	org, ok := m.orgs[id]
	if !ok {
		return nil, nil
	}
	return org, nil
}

// GetBySlug returns an organization by slug.
func (m *MockOrgRepo) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	org, ok := m.orgs[slug]
	if !ok {
		return nil, nil
	}
	return org, nil
}

// Update replaces an organization.
func (m *MockOrgRepo) Update(ctx context.Context, org *domain.Organization) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orgs[org.ID] = org
	return nil
}

// Delete removes an organization.
func (m *MockOrgRepo) Delete(ctx context.Context, id string) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.orgs[id]; !ok {
		return false, nil
	}
	delete(m.orgs, id)
	return true, nil
}

// AddMember stores an organization membership.
func (m *MockOrgRepo) AddMember(ctx context.Context, member *domain.OrgMember) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	key := member.OrgID + ":" + member.UserID
	if _, ok := m.members[key]; ok {
		// Mirrors sqlstore's unique-constraint translation
		// (port.ErrDuplicateKey) on (org_id, user_id), so tests exercise
		// the same contract the real repository honors.
		return port.ErrDuplicateKey
	}
	m.members[key] = member
	return nil
}

// RemoveMember removes a matching organization membership.
func (m *MockOrgRepo) RemoveMember(ctx context.Context, orgID, userID string, expectRole domain.OrgRole) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID + ":" + userID
	mem, ok := m.members[key]
	if !ok || mem.Role != expectRole {
		return false, nil
	}
	delete(m.members, key)
	return true, nil
}

// UpdateMemberRole changes a matching membership role.
func (m *MockOrgRepo) UpdateMemberRole(ctx context.Context, orgID, userID string, expectRole, newRole domain.OrgRole) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID + ":" + userID
	mem, ok := m.members[key]
	if !ok || mem.Role != expectRole {
		return false, nil
	}
	mem.Role = newRole
	return true, nil
}

// GetMembership returns an organization membership.
func (m *MockOrgRepo) GetMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error) {
	recordMockTx(ctx, m)
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
	// Return a copy, like sqlstore's per-query scan: callers must not
	// observe another goroutine's in-flight CAS mutation through a shared
	// struct, and must not mutate mock state through the result.
	cp := *mem
	return &cp, nil
}

// LockMembership mirrors the transaction-scoped lookup for service tests.
func (m *MockOrgRepo) LockMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error) {
	recordMockTx(ctx, m)
	return m.GetMembership(ctx, orgID, userID)
}

// CountMembers returns the number of matching organization members.
func (m *MockOrgRepo) CountMembers(ctx context.Context, orgID string, filter port.OrgMemberFilter) (int, error) {
	recordMockTx(ctx, m)
	f := filter
	f.Limit, f.Offset = 0, 0
	items, err := m.ListMembers(ctx, orgID, f)
	return len(items), err
}

// ListMembers returns matching organization members.
func (m *MockOrgRepo) ListMembers(ctx context.Context, orgID string, filter port.OrgMemberFilter) ([]domain.OrgMemberDetail, error) {
	recordMockTx(ctx, m)
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
		page = []domain.OrgMemberDetail{}
	}
	return page, nil
}

// CountUserOrgs returns the number of matching organizations for a user.
func (m *MockOrgRepo) CountUserOrgs(ctx context.Context, userID string, filter port.UserOrgFilter) (int, error) {
	recordMockTx(ctx, m)
	f := filter
	f.Limit, f.Offset = 0, 0
	items, err := m.ListUserOrgs(ctx, userID, f)
	return len(items), err
}

// ListUserOrgs returns matching organizations for a user.
func (m *MockOrgRepo) ListUserOrgs(ctx context.Context, userID string, filter port.UserOrgFilter) ([]domain.Organization, error) {
	recordMockTx(ctx, m)
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
		page = []domain.Organization{}
	}
	return page, nil
}

// Count returns the number of matching organizations.
func (m *MockOrgRepo) Count(ctx context.Context, filter port.OrgFilter) (int, error) {
	recordMockTx(ctx, m)
	f := filter
	f.Limit, f.Offset = 0, 0
	items, err := m.List(ctx, f)
	return len(items), err
}

// List returns matching organizations.
func (m *MockOrgRepo) List(ctx context.Context, filter port.OrgFilter) ([]domain.Organization, error) {
	recordMockTx(ctx, m)
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
		page = []domain.Organization{}
	}
	return page, nil
}

// IncrementUserOrgOwnerCount increments a user's owned organization count within the limit.
func (m *MockOrgRepo) IncrementUserOrgOwnerCount(ctx context.Context, userID string, maxOrgs int) error {
	recordMockTx(ctx, m)
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

// DecrementUserOrgOwnerCount decrements a user's owned organization count.
func (m *MockOrgRepo) DecrementUserOrgOwnerCount(ctx context.Context, _ string) error {
	recordMockTx(ctx, m)
	return nil
}

// IncrementOrgMemberCount increments an organization's member count.
func (m *MockOrgRepo) IncrementOrgMemberCount(ctx context.Context, _ string, _ int) error {
	recordMockTx(ctx, m)
	return nil
}

// DecrementOrgMemberCount decrements an organization's member count.
func (m *MockOrgRepo) DecrementOrgMemberCount(ctx context.Context, _ string) error {
	recordMockTx(ctx, m)
	return nil
}

// TryDecrementOrgOwnerCount decrements an organization's owner count unless it is the last owner.
func (m *MockOrgRepo) TryDecrementOrgOwnerCount(ctx context.Context, orgID string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	// The service runs its guarded membership delete/update BEFORE this
	// upkeep, so by the time this evaluates, the row being removed or
	// demoted is already gone from the map — mirroring the real
	// denormalized owner_count only if we refuse on zero remaining owners,
	// not on one. (The real SQL guard is `owner_count > 1` on a counter the
	// membership write does not touch; here the live rows ARE the counter.)
	count := 0
	for _, mem := range m.members {
		if mem.OrgID == orgID && mem.Role == domain.OrgRoleOwner {
			count++
		}
	}
	if count < 1 {
		return domain.ErrCannotRemoveLastOwner
	}
	return nil
}

// IncrementOrgOwnerCount increments an organization's owner count.
func (m *MockOrgRepo) IncrementOrgOwnerCount(ctx context.Context, _ string) error {
	recordMockTx(ctx, m)
	return nil
}

// DecrementOwnerCountForOrgOwners decrements the owned count for an organization's owners.
func (m *MockOrgRepo) DecrementOwnerCountForOrgOwners(ctx context.Context, _ string) error {
	recordMockTx(ctx, m)
	return nil
}
