package testutil

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// MockUserRepo is an in-memory user repository for tests. Stored users and
// read results are detached snapshots, including their optional pointer fields.
type MockUserRepo struct {
	mu    sync.Mutex
	users map[string]*domain.User
	// claimedSetPassTokens tracks the set-password token IDs consumed through
	// SetPasswordAndVerify, mirroring the real repository's one-time-claim
	// contract so tests exercise the same single-use semantics.
	claimedSetPassTokens map[string]bool
}

// NewMockUserRepo returns an in-memory user repository.
func NewMockUserRepo() *MockUserRepo {
	return &MockUserRepo{users: make(map[string]*domain.User)}
}

// Create stores a user.
func (m *MockUserRepo) Create(ctx context.Context, user *domain.User) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	// Check for duplicate email — mirrors sqlstore's unique-constraint
	// translation (port.ErrDuplicateKey), not a pre-built domain error, so a
	// test against this mock exercises the same contract the real
	// UserRepository.Create honors.
	for _, u := range m.users {
		if u.Email == user.Email && u.ID != user.ID {
			return port.ErrDuplicateKey
		}
	}
	stored := cloneUser(user)
	m.users[user.ID] = stored
	m.users[user.Email] = stored
	return nil
}

// GetByID returns a user by ID.
func (m *MockUserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, nil
	}
	return cloneUser(u), nil
}

// GetByEmail returns a user by email.
func (m *MockUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[email]
	if !ok {
		return nil, nil
	}
	return cloneUser(u), nil
}

// Update replaces a user.
func (m *MockUserRepo) Update(ctx context.Context, user *domain.User) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.users[user.ID]; old != nil {
		delete(m.users, old.Email)
	}
	stored := cloneUser(user)
	m.users[user.ID] = stored
	m.users[user.Email] = stored
	return nil
}

// Delete removes a user.
func (m *MockUserRepo) Delete(ctx context.Context, id string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	if u != nil {
		delete(m.users, u.Email)
	}
	delete(m.users, id)
	return nil
}

// List returns matching users.
func (m *MockUserRepo) List(ctx context.Context, filter port.UserFilter) ([]domain.User, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()

	var matched []domain.User
	seen := make(map[string]bool)
	for _, u := range m.users {
		if u.ID == "" || seen[u.ID] {
			continue
		}
		if !userMatchesFilter(u, filter) {
			continue
		}
		seen[u.ID] = true
		matched = append(matched, *cloneUser(u))
	}

	sort.SliceStable(matched, func(i, j int) bool {
		var ci, cj time.Time
		if filter.OrderBy == "updated_at" {
			ci, cj = matched[i].UpdatedAt, matched[j].UpdatedAt
		} else {
			ci, cj = matched[i].CreatedAt, matched[j].CreatedAt
		}
		if filter.OrderDirection == api.SortAscending {
			return ci.Before(cj)
		}
		return ci.After(cj)
	})

	if filter.Limit <= 0 {
		return matched, nil
	}
	start := filter.Offset
	if start > len(matched) {
		start = len(matched)
	}
	end := start + filter.Limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], nil
}

// Count returns the number of matching users.
func (m *MockUserRepo) Count(ctx context.Context, filter port.UserFilter) (int, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()

	seen := make(map[string]bool)
	n := 0
	for _, u := range m.users {
		if u.ID == "" || seen[u.ID] {
			continue
		}
		if userMatchesFilter(u, filter) {
			seen[u.ID] = true
			n++
		}
	}
	return n, nil
}

// CountByDay groups matched users by their CreatedAt day — a small in-memory
// stand-in for the real GROUP BY date_trunc('day', ...) query.
func (m *MockUserRepo) CountByDay(ctx context.Context, filter port.UserFilter) ([]api.DailyCount, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()

	byDay := make(map[time.Time]int)
	seen := make(map[string]bool)
	for _, u := range m.users {
		if u.ID == "" || seen[u.ID] {
			continue
		}
		if !userMatchesFilter(u, filter) {
			continue
		}
		seen[u.ID] = true
		day := time.Date(u.CreatedAt.Year(), u.CreatedAt.Month(), u.CreatedAt.Day(), 0, 0, 0, 0, time.UTC)
		byDay[day]++
	}

	counts := make([]api.DailyCount, 0, len(byDay))
	for day, count := range byDay {
		counts = append(counts, api.DailyCount{Date: day, Count: count})
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].Date.Before(counts[j].Date) })
	return counts, nil
}

func userMatchesFilter(u *domain.User, filter port.UserFilter) bool {
	if len(filter.IDs) > 0 && !slices.Contains(filter.IDs, u.ID) {
		return false
	}
	if filter.Email != nil && !strings.Contains(strings.ToLower(u.Email), strings.ToLower(*filter.Email)) {
		return false
	}
	if filter.Role != nil && u.Role != *filter.Role {
		return false
	}
	if filter.IsBanned != nil && u.IsBanned != *filter.IsBanned {
		return false
	}
	if filter.IsVerified != nil && u.IsVerified != *filter.IsVerified {
		return false
	}
	if filter.TwoFactorEnabled != nil && u.TwoFactorEnabled != *filter.TwoFactorEnabled {
		return false
	}
	if filter.NeverLoggedIn != nil && *filter.NeverLoggedIn && u.LastLoginAt != nil {
		return false
	}
	if filter.LastLoginBefore != nil && (u.LastLoginAt == nil || !u.LastLoginAt.Before(*filter.LastLoginBefore)) {
		return false
	}
	if filter.CreatedAfter != nil && u.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}
	if filter.CreatedBefore != nil && u.CreatedAt.After(*filter.CreatedBefore) {
		return false
	}
	if filter.Search != nil && *filter.Search != "" {
		s := strings.ToLower(*filter.Search)
		if !strings.Contains(strings.ToLower(u.Name), s) && !strings.Contains(strings.ToLower(u.Email), s) {
			return false
		}
	}
	return true
}

// SetBanStatus changes a user's ban status.
func (m *MockUserRepo) SetBanStatus(ctx context.Context, userID string, isBanned bool, bannedAt *time.Time, _ time.Time) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return nil
	}
	u.IsBanned = isBanned
	u.BannedAt = clonePointer(bannedAt)
	return nil
}

// SetTwoFactorEnabled changes a user's two-factor status.
func (m *MockUserRepo) SetTwoFactorEnabled(ctx context.Context, userID string, enabled bool, updatedAt time.Time) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return nil
	}
	u.TwoFactorEnabled = enabled
	u.UpdatedAt = updatedAt
	return nil
}

// UpdateLastLoginAt records a user's last login time.
func (m *MockUserRepo) UpdateLastLoginAt(ctx context.Context, userID string, t time.Time) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return nil
	}
	u.LastLoginAt = &t
	return nil
}

// UpdatePasswordHash replaces a matching password hash.
func (m *MockUserRepo) UpdatePasswordHash(ctx context.Context, userID, oldHash string, oldPepperVersion *uint32, newHash string, newPepperVersion *uint32, updatedAt time.Time) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok || u.PasswordHash == nil || *u.PasswordHash != oldHash ||
		!sameUint32Pointer(u.PasswordPepperVersion, oldPepperVersion) ||
		pepperVersionValue(newPepperVersion) < pepperVersionValue(oldPepperVersion) {
		return false, nil
	}
	u.PasswordHash = &newHash
	u.PasswordPepperVersion = cloneUint32Pointer(newPepperVersion)
	u.UpdatedAt = updatedAt
	return true, nil
}

// UpdateName changes only name and updated_at — the guarded write the
// service layer requires. False means the user no longer exists.
func (m *MockUserRepo) UpdateName(ctx context.Context, userID, name string, updatedAt time.Time) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return false, nil
	}
	u.Name = name
	u.UpdatedAt = updatedAt
	return true, nil
}

// VerifyEmailIfMatches sets verification fields only while the stored email
// still matches — the conditional write the service layer requires.
func (m *MockUserRepo) VerifyEmailIfMatches(ctx context.Context, userID, expectedEmail string, verifiedAt time.Time) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok || u.Email != expectedEmail {
		return false, nil
	}
	u.IsVerified = true
	u.VerifiedAt = &verifiedAt
	u.UpdatedAt = verifiedAt
	return true, nil
}

// WithAdminGuard gives guarded mutations the same callback rollback model as
// MockTxManager. SQL fixtures verify the actual account-mutation locks.
func (m *MockUserRepo) WithAdminGuard(ctx context.Context, fn func(context.Context) error) error {
	return (&MockTxManager{}).WithTx(ctx, func(txCtx context.Context) error {
		recordMockTx(txCtx, m)
		return fn(txCtx)
	})
}

func (m *MockUserRepo) mockUsableAdminLocked(exceptID string) bool {
	for _, u := range m.users {
		if u.ID == "" || u.ID == exceptID {
			continue
		}
		if u.Role == domain.RoleAdmin && !u.IsBanned {
			return true
		}
	}
	return false
}

// DeleteWithAdminGuard deletes the user unless it is the last usable admin.
func (m *MockUserRepo) DeleteWithAdminGuard(ctx context.Context, userID string) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return false, domain.ErrUserNotFound
	}
	if u.Role == domain.RoleAdmin && !u.IsBanned && !m.mockUsableAdminLocked(userID) {
		return false, nil
	}
	delete(m.users, u.Email)
	delete(m.users, userID)
	return true, nil
}

// BanWithAdminGuard sets ban status unless banning would remove the last usable admin.
func (m *MockUserRepo) BanWithAdminGuard(ctx context.Context, userID string, isBanned bool, bannedAt *time.Time, updatedAt time.Time) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return false, domain.ErrUserNotFound
	}
	if isBanned && u.Role == domain.RoleAdmin && !u.IsBanned && !m.mockUsableAdminLocked(userID) {
		return false, nil
	}
	u.IsBanned = isBanned
	u.BannedAt = clonePointer(bannedAt)
	u.UpdatedAt = updatedAt
	return true, nil
}

// DemoteWithAdminGuard sets the role unless demoting from admin would remove
// the last usable admin. Promotions are always allowed.
func (m *MockUserRepo) DemoteWithAdminGuard(ctx context.Context, userID string, role domain.Role, updatedAt time.Time) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return false, domain.ErrUserNotFound
	}
	if role != domain.RoleAdmin && u.Role == domain.RoleAdmin && !u.IsBanned && !m.mockUsableAdminLocked(userID) {
		return false, nil
	}
	u.Role = role
	u.UpdatedAt = updatedAt
	return true, nil
}

// SetPasswordAndVerify consumes a token, sets a password, and verifies a user.
func (m *MockUserRepo) SetPasswordAndVerify(ctx context.Context, userID string, passwordHash string, pepperVersion *uint32, tokenID string) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return false, nil
	}
	if m.claimedSetPassTokens == nil {
		m.claimedSetPassTokens = make(map[string]bool)
	}
	if m.claimedSetPassTokens[tokenID] {
		return false, nil
	}
	if u.PasswordHash != nil {
		return false, nil
	}
	now := time.Now().UTC()
	u.PasswordHash = &passwordHash
	u.PasswordPepperVersion = cloneUint32Pointer(pepperVersion)
	u.IsVerified = true
	u.VerifiedAt = &now
	u.UpdatedAt = now
	m.claimedSetPassTokens[tokenID] = true
	return true, nil
}

// ListPasswordPepperVersions returns stored password pepper versions.
func (m *MockUserRepo) ListPasswordPepperVersions(ctx context.Context) ([]uint32, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	seen := make(map[uint32]struct{})
	for _, u := range m.users {
		if u.PasswordPepperVersion != nil {
			seen[*u.PasswordPepperVersion] = struct{}{}
		}
	}
	versions := make([]uint32, 0, len(seen))
	for version := range seen {
		versions = append(versions, version)
	}
	slices.Sort(versions)
	return versions, nil
}

func sameUint32Pointer(a, b *uint32) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

func cloneUint32Pointer(value *uint32) *uint32 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}

func pepperVersionValue(value *uint32) uint32 {
	if value == nil {
		return 0
	}
	return *value
}

// ─── MockAuditPublisher ──────────────────────────────────────────────
