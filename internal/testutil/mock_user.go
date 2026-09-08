package testutil

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

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
	// Check for duplicate email — mirrors sqlstore's unique-constraint
	// translation (port.ErrDuplicateKey), not a pre-built domain error, so a
	// test against this mock exercises the same contract the real
	// UserRepository.Create honors.
	for _, u := range m.users {
		if u.Email == user.Email && u.ID != user.ID {
			return port.ErrDuplicateKey
		}
	}
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

func (m *MockUserRepo) List(_ context.Context, filter port.UserFilter) ([]domain.User, error) {
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
		matched = append(matched, *u)
	}

	sort.SliceStable(matched, func(i, j int) bool {
		var ci, cj time.Time
		if filter.OrderBy == "updated_at" {
			ci, cj = matched[i].UpdatedAt, matched[j].UpdatedAt
		} else {
			ci, cj = matched[i].CreatedAt, matched[j].CreatedAt
		}
		if strings.EqualFold(filter.OrderDirection, "asc") {
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

func (m *MockUserRepo) Count(_ context.Context, filter port.UserFilter) (int, error) {
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
func (m *MockUserRepo) CountByDay(_ context.Context, filter port.UserFilter) ([]port.DailyCount, error) {
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

	counts := make([]port.DailyCount, 0, len(byDay))
	for day, count := range byDay {
		counts = append(counts, port.DailyCount{Date: day, Count: count})
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

func (m *MockUserRepo) SetTwoFactorEnabled(_ context.Context, userID string, enabled bool, updatedAt time.Time) error {
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

func (m *MockUserRepo) UpdateLastLoginAt(_ context.Context, userID string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return nil
	}
	u.LastLoginAt = &t
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

// ─── MockAuditPublisher ──────────────────────────────────────────────
