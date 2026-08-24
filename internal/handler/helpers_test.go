package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

type mockUserRepo struct {
	mu    sync.Mutex
	users map[string]*domain.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*domain.User)}
}

func (m *mockUserRepo) Create(_ context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.users {
		if u.Email == user.Email && u.ID != user.ID {
			// Mirrors sqlstore's unique-constraint translation
			// (port.ErrDuplicateKey), not a pre-built domain error, so this
			// mock exercises the same contract the real repository honors.
			return port.ErrDuplicateKey
		}
	}
	m.users[user.ID] = user
	m.users[user.Email] = user
	return nil
}

func (m *mockUserRepo) GetByID(_ context.Context, id string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[email]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *mockUserRepo) Update(_ context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.users[user.Email] = user
	return nil
}

func (m *mockUserRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	if u != nil {
		delete(m.users, u.Email)
	}
	delete(m.users, id)
	return nil
}

func (m *mockUserRepo) List(_ context.Context, filter port.UserFilter) ([]domain.User, int, error) {
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

	total := len(matched)
	if filter.Limit <= 0 {
		return matched, total, nil
	}
	start := filter.Offset
	if start > len(matched) {
		start = len(matched)
	}
	end := start + filter.Limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

// CountByDay groups matched users by their CreatedAt day — a small in-memory
// stand-in for the real GROUP BY date_trunc('day', ...) query.
func (m *mockUserRepo) CountByDay(_ context.Context, filter port.UserFilter) ([]port.DailyCount, error) {
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

func (m *mockUserRepo) SetBanStatus(_ context.Context, userID string, isBanned bool, bannedAt *time.Time, _ time.Time) error {
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

func (m *mockUserRepo) SetTwoFactorEnabled(_ context.Context, userID string, enabled bool, updatedAt time.Time) error {
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

func (m *mockUserRepo) UpdateLastLoginAt(_ context.Context, userID string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[userID]
	if !ok {
		return nil
	}
	u.LastLoginAt = &t
	return nil
}

func (m *mockUserRepo) SetPasswordAndVerify(_ context.Context, userID string, passwordHash string, tokenID string) error {
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

type mockAuditLogRepo struct {
	mu      sync.Mutex
	entries []port.AuditLogEntry
}

func newMockAuditLogRepo() *mockAuditLogRepo {
	return &mockAuditLogRepo{}
}

func (m *mockAuditLogRepo) AddEntry(e port.AuditLogEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
}

func (m *mockAuditLogRepo) List(_ context.Context, filter port.AuditLogFilter) ([]port.AuditLogEntry, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var matched []port.AuditLogEntry
	for _, e := range m.entries {
		if auditEntryMatchesFilter(e, filter) {
			matched = append(matched, e)
		}
	}
	sort.SliceStable(matched, func(i, j int) bool { return matched[i].CreatedAt.After(matched[j].CreatedAt) })

	total := len(matched)
	if filter.Limit <= 0 {
		return matched, total, nil
	}
	start := filter.Offset
	if start > len(matched) {
		start = len(matched)
	}
	end := start + filter.Limit
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

func (m *mockAuditLogRepo) GetByID(_ context.Context, id string) (*port.AuditLogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e.ID == id {
			cp := e
			return &cp, nil
		}
	}
	return nil, nil
}

func (m *mockAuditLogRepo) CountByDay(_ context.Context, filter port.AuditLogFilter) ([]port.DailyCount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	byDay := make(map[time.Time]int)
	for _, e := range m.entries {
		if !auditEntryMatchesFilter(e, filter) {
			continue
		}
		day := time.Date(e.CreatedAt.Year(), e.CreatedAt.Month(), e.CreatedAt.Day(), 0, 0, 0, 0, time.UTC)
		byDay[day]++
	}

	counts := make([]port.DailyCount, 0, len(byDay))
	for day, count := range byDay {
		counts = append(counts, port.DailyCount{Date: day, Count: count})
	}
	sort.Slice(counts, func(i, j int) bool { return counts[i].Date.Before(counts[j].Date) })
	return counts, nil
}

func auditEntryMatchesFilter(e port.AuditLogEntry, filter port.AuditLogFilter) bool {
	if len(filter.Types) > 0 && !slices.Contains(filter.Types, e.Type) {
		return false
	}
	if filter.ActorID != nil && (e.ActorID == nil || *e.ActorID != *filter.ActorID) {
		return false
	}
	if filter.TargetUserID != nil && (e.TargetUserID == nil || *e.TargetUserID != *filter.TargetUserID) {
		return false
	}
	if filter.SessionID != nil && (e.SessionID == nil || *e.SessionID != *filter.SessionID) {
		return false
	}
	if filter.OrgID != nil && (e.OrgID == nil || *e.OrgID != *filter.OrgID) {
		return false
	}
	if filter.DeviceType != nil && *filter.DeviceType != "" {
		var ua domain.UserAgentInfo
		if err := json.Unmarshal(e.ParsedUA, &ua); err != nil || ua.DeviceType != *filter.DeviceType {
			return false
		}
	}
	if filter.IP != nil && *filter.IP != "" && e.IP != *filter.IP {
		return false
	}
	if filter.Success != nil && e.Success != *filter.Success {
		return false
	}
	if filter.FromDate != nil && e.CreatedAt.Before(*filter.FromDate) {
		return false
	}
	if filter.ToDate != nil && e.CreatedAt.After(*filter.ToDate) {
		return false
	}
	if filter.Search != nil && *filter.Search != "" {
		s := strings.ToLower(*filter.Search)
		matches := strings.Contains(strings.ToLower(e.UserAgent), s) ||
			strings.Contains(strings.ToLower(string(e.Metadata)), s) ||
			strings.Contains(strings.ToLower(e.IP), s) ||
			strings.Contains(strings.ToLower(e.Type), s)
		if !matches {
			return false
		}
	}
	return true
}

type mockSessionRepo struct {
	mu            sync.Mutex
	sessions      map[string]*domain.Session
	byID          map[string]*domain.Session
	byRefreshHash map[string]*domain.Session
	// clearActiveOrgCalls records session IDs passed to ClearActiveOrg.
	clearActiveOrgCalls []string
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{
		sessions:      make(map[string]*domain.Session),
		byID:          make(map[string]*domain.Session),
		byRefreshHash: make(map[string]*domain.Session),
	}
}

func (m *mockSessionRepo) Create(_ context.Context, s *domain.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.TokenHash] = s
	m.byID[s.ID] = s
	if s.RefreshTokenHash != "" {
		m.byRefreshHash[s.RefreshTokenHash] = s
	}
	return nil
}

func (m *mockSessionRepo) GetByTokenHash(_ context.Context, hash string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *mockSessionRepo) GetByRefreshHash(_ context.Context, hash string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byRefreshHash[hash]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *mockSessionRepo) GetByPreviousRefreshHash(_ context.Context, hash string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.byID {
		if s.PreviousRefreshHash == hash {
			return s, nil
		}
	}
	return nil, nil
}

func (m *mockSessionRepo) LockAndGetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	return m.GetByRefreshHash(ctx, hash)
}

func (m *mockSessionRepo) ListByUserID(_ context.Context, userID string, offset, limit int) ([]domain.Session, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []domain.Session
	for _, s := range m.byID {
		if s.UserID == userID {
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

func (m *mockSessionRepo) ListAllByUserID(_ context.Context, userID string) ([]domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []domain.Session
	for _, s := range m.byID {
		if s.UserID == userID {
			res = append(res, *s)
		}
	}
	return res, nil
}

func (m *mockSessionRepo) ListAll(_ context.Context, filter port.SessionFilter) ([]domain.Session, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []domain.Session
	for _, s := range m.byID {
		if filter.UserID != nil && s.UserID != *filter.UserID {
			continue
		}
		res = append(res, *s)
	}
	total := len(res)
	if filter.Offset > 0 && filter.Offset < total {
		res = res[filter.Offset:]
	} else if filter.Offset >= total {
		res = []domain.Session{}
	}
	if filter.Limit > 0 && filter.Limit < len(res) {
		res = res[:filter.Limit]
	}
	return res, total, nil
}

func (m *mockSessionRepo) Delete(_ context.Context, tokenHash string) error {
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

func (m *mockSessionRepo) DeleteByID(_ context.Context, id string) error {
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

func (m *mockSessionRepo) RevokeByIDForUser(_ context.Context, id, userID string) (bool, error) {
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

func (m *mockSessionRepo) RevokeManyForUser(_ context.Context, ids []string, userID string) (int, error) {
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

func (m *mockSessionRepo) DeleteAllForUser(_ context.Context, userID string) error {
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

func (m *mockSessionRepo) DeleteAllForUserExcept(_ context.Context, userID string, exceptSessionID string) error {
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

func (m *mockSessionRepo) DeleteExpired(_ context.Context) error {
	return nil
}

func (m *mockSessionRepo) UpdateLastActiveAt(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[tokenHash]; ok {
		s.LastActiveAt = time.Now().UTC()
	}
	return nil
}

func (m *mockSessionRepo) UpdateRefreshToken(_ context.Context, input port.UpdateRefreshInput) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

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

func (m *mockSessionRepo) UpdateActiveOrgRoleForUser(_ context.Context, userID, orgID string, newRole domain.OrgRole) error {
	return nil
}

func (m *mockSessionRepo) ClearActiveOrgForUser(_ context.Context, userID, orgID string) error {
	return nil
}

func (m *mockSessionRepo) ClearActiveOrg(_ context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clearActiveOrgCalls = append(m.clearActiveOrgCalls, sessionID)
	return nil
}

func (m *mockSessionRepo) ClearActiveOrgForAllMembers(_ context.Context, orgID string) error {
	return nil
}

func (m *mockSessionRepo) SetActiveOrg(_ context.Context, sessionID, orgID string, role domain.OrgRole) error {
	return nil
}

type mockTokenRepo struct {
	mu     sync.Mutex
	tokens map[string]*domain.VerificationToken
}

func newMockTokenRepo() *mockTokenRepo {
	return &mockTokenRepo{tokens: make(map[string]*domain.VerificationToken)}
}

func (m *mockTokenRepo) Create(_ context.Context, t *domain.VerificationToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.ID] = t
	m.tokens[t.TokenHash] = t
	return nil
}

func (m *mockTokenRepo) GetByHash(_ context.Context, hash string) (*domain.VerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[hash]
	if !ok {
		return nil, nil
	}
	return t, nil
}

func (m *mockTokenRepo) MarkUsed(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if ok {
		now := time.Now().UTC()
		t.UsedAt = &now
	}
	return nil
}

func (m *mockTokenRepo) GetByID(_ context.Context, id string) (*domain.VerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tokens {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, nil
}

func (m *mockTokenRepo) IncrementAttempts(_ context.Context, id string, maxAttemptsPerChallenge int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tokens {
		if t.ID == id {
			if t.Attempts >= maxAttemptsPerChallenge {
				return false, nil
			}
			t.Attempts++
			return true, nil
		}
	}
	return false, nil
}

func (m *mockTokenRepo) MarkUsedIfUnderCap(_ context.Context, id string, maxAttemptsPerChallenge int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tokens {
		if t.ID == id {
			if t.UsedAt != nil || t.Attempts >= maxAttemptsPerChallenge {
				return false, nil
			}
			now := time.Now().UTC()
			t.UsedAt = &now
			return true, nil
		}
	}
	return false, nil
}

func (m *mockTokenRepo) UpdateForResend(_ context.Context, id string, newHash string, newExpiresAt time.Time, maxRefreshesPerChallenge, maxAttemptsPerChallenge int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash, t := range m.tokens {
		if t.ID == id {
			if t.UsedAt != nil || t.ResendCount >= maxRefreshesPerChallenge || t.Attempts >= maxAttemptsPerChallenge {
				return false, nil
			}
			delete(m.tokens, hash)
			t.TokenHash = newHash
			t.ExpiresAt = newExpiresAt
			t.ResendCount++
			m.tokens[newHash] = t
			return true, nil
		}
	}
	return false, nil
}

func (m *mockTokenRepo) DeleteExpired(_ context.Context) error {
	return nil
}

func (m *mockTokenRepo) DeleteUnusedByUserAndType(_ context.Context, userID string, tokenType domain.TokenType) error {
	return nil
}

func (m *mockTokenRepo) GetLastByUserAndType(_ context.Context, userID string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var last *domain.VerificationToken
	for _, t := range m.tokens {
		if t.UserID != nil && *t.UserID == userID && t.Type == tokenType {
			if last == nil || t.CreatedAt.After(last.CreatedAt) {
				last = t
			}
		}
	}
	return last, nil
}

func (m *mockTokenRepo) HasValidByUserAndType(_ context.Context, userID string, tokenType domain.TokenType) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, t := range m.tokens {
		if t.UserID != nil && *t.UserID == userID && t.Type == tokenType && t.UsedAt == nil && now.Before(t.ExpiresAt) {
			return true, nil
		}
	}
	return false, nil
}

type mockTokenGen struct {
	counter int64
}

func (m *mockTokenGen) Generate() (string, error) {
	m.counter++
	b := sha256.Sum256(fmt.Appendf(nil, "%s-%d", time.Now().String(), m.counter))
	return hex.EncodeToString(b[:16]), nil
}

type mockHasher struct{}

func (m *mockHasher) Hash(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]), nil
}

func (m *mockHasher) Compare(password, hash string) error {
	sum := sha256.Sum256([]byte(password))
	if hex.EncodeToString(sum[:]) != hash {
		return domain.ErrInvalidCredentials
	}
	return nil
}

type mockMailer struct {
	SendFn func(ctx context.Context, to, subject, html, text string) error
	Calls  []struct{ To, Subject, HTML, Text string }
}

func (m *mockMailer) Send(ctx context.Context, to, subject, html, text string) error {
	m.Calls = append(m.Calls, struct{ To, Subject, HTML, Text string }{to, subject, html, text})
	if m.SendFn != nil {
		return m.SendFn(ctx, to, subject, html, text)
	}
	return nil
}

// ─── mockOrgRepo ─────────────────────────────────────────────────────

type mockOrgRepo struct {
	mu      sync.Mutex
	orgs    map[string]*domain.Organization
	members map[string]*domain.OrgMember
	// users resolves a member's User for ListMembers (name/email search and
	// populating OrgMemberDetail.User) — wired in newTestHarness.
	users *mockUserRepo
}

func newMockOrgRepo() *mockOrgRepo {
	return &mockOrgRepo{
		orgs:    make(map[string]*domain.Organization),
		members: make(map[string]*domain.OrgMember),
	}
}

func (m *mockOrgRepo) Create(_ context.Context, org *domain.Organization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.orgs[org.ID] = org
	m.orgs[org.Slug] = org
	return nil
}

func (m *mockOrgRepo) GetByID(_ context.Context, id string) (*domain.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	org, ok := m.orgs[id]
	if !ok {
		return nil, nil
	}
	return org, nil
}

func (m *mockOrgRepo) GetBySlug(_ context.Context, slug string) (*domain.Organization, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	org, ok := m.orgs[slug]
	if !ok {
		return nil, nil
	}
	return org, nil
}

func (m *mockOrgRepo) Update(_ context.Context, org *domain.Organization) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.orgs, org.Slug)
	m.orgs[org.ID] = org
	m.orgs[org.Slug] = org
	return nil
}

func (m *mockOrgRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if org, ok := m.orgs[id]; ok {
		delete(m.orgs, org.Slug)
	}
	delete(m.orgs, id)
	return nil
}

func (m *mockOrgRepo) AddMember(_ context.Context, member *domain.OrgMember) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := member.OrgID + ":" + member.UserID
	m.members[key] = member
	return nil
}

func (m *mockOrgRepo) RemoveMember(_ context.Context, orgID, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID + ":" + userID
	delete(m.members, key)
	return nil
}

func (m *mockOrgRepo) UpdateMemberRole(_ context.Context, orgID, userID string, role domain.OrgRole) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID + ":" + userID
	if mem, ok := m.members[key]; ok {
		mem.Role = role
	}
	return nil
}

func (m *mockOrgRepo) GetMembership(_ context.Context, orgID, userID string) (*domain.OrgMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID + ":" + userID
	mem, ok := m.members[key]
	if !ok {
		return nil, nil
	}
	return mem, nil
}

func (m *mockOrgRepo) ListMembers(ctx context.Context, orgID string, filter port.OrgMemberFilter) ([]domain.OrgMemberDetail, int, error) {
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
	return page, total, nil
}

func (m *mockOrgRepo) ListUserOrgs(_ context.Context, userID string, filter port.UserOrgFilter) ([]domain.Organization, int, error) {
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
	return page, total, nil
}

func (m *mockOrgRepo) List(_ context.Context, filter port.OrgFilter) ([]domain.Organization, int, error) {
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
	return page, total, nil
}

func (m *mockOrgRepo) IncrementUserOrgOwnerCount(_ context.Context, userID string, maxOrgs int) error {
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

func (m *mockOrgRepo) DecrementUserOrgOwnerCount(_ context.Context, userID string) error {
	return nil
}

func (m *mockOrgRepo) IncrementOrgMemberCount(_ context.Context, orgID string, maxMembers int) error {
	return nil
}

func (m *mockOrgRepo) DecrementOrgMemberCount(_ context.Context, orgID string) error {
	return nil
}

func (m *mockOrgRepo) TryDecrementOrgOwnerCount(_ context.Context, orgID string) error {
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

func (m *mockOrgRepo) IncrementOrgOwnerCount(_ context.Context, orgID string) error {
	return nil
}

func (m *mockOrgRepo) DecrementOwnerCountForOrgOwners(_ context.Context, orgID string) error {
	return nil
}

// ─── mockOrgInviteRepo ───────────────────────────────────────────────

type mockOrgInviteRepo struct {
	mu      sync.Mutex
	invites map[string]*domain.OrgInvite
}

func newMockOrgInviteRepo() *mockOrgInviteRepo {
	return &mockOrgInviteRepo{invites: make(map[string]*domain.OrgInvite)}
}

func (m *mockOrgInviteRepo) Create(_ context.Context, invite *domain.OrgInvite) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.invites[invite.ID] = invite
	m.invites["hash:"+invite.CodeHash] = invite
	return nil
}

func (m *mockOrgInviteRepo) GetByID(_ context.Context, id string) (*domain.OrgInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *mockOrgInviteRepo) GetByCodeHash(_ context.Context, codeHash string) (*domain.OrgInvite, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites["hash:"+codeHash]
	if !ok {
		return nil, nil
	}
	return inv, nil
}

func (m *mockOrgInviteRepo) ListByOrgID(_ context.Context, orgID string, filter port.OrgInviteFilter) ([]domain.OrgInvite, int, error) {
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
		page = []domain.OrgInvite{}
	}
	return page, total, nil
}

func (m *mockOrgInviteRepo) Update(_ context.Context, invite *domain.OrgInvite) error {
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

func (m *mockOrgInviteRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if inv, ok := m.invites[id]; ok {
		delete(m.invites, id)
		delete(m.invites, "hash:"+inv.CodeHash)
	}
	return nil
}

func (m *mockOrgInviteRepo) ClaimInvite(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invites[id]
	if !ok || time.Now().UTC().After(inv.ExpiresAt) {
		return false, nil
	}
	delete(m.invites, id)
	delete(m.invites, "hash:"+inv.CodeHash)
	return true, nil
}

// ─── mockTxManager ───────────────────────────────────────────────────

type mockTxManager struct{}

func (m *mockTxManager) WithTx(_ context.Context, fn func(ctx context.Context) error) error {
	return fn(context.Background())
}

// ─── testHarness ─────────────────────────────────────────────────────

type testHarness struct {
	handler    *Handler
	users      *mockUserRepo
	sessions   *mockSessionRepo
	tokens     *mockTokenRepo
	mailer     *mockMailer
	orgs       *mockOrgRepo
	orgInvites *mockOrgInviteRepo
	providers  *mockProviderAccountRepo
	auditLogs  *mockAuditLogRepo
	twoFactor  *service.TwoFactorService
}

func newTestHarness() *testHarness {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{}
	mailer := &mockMailer{}
	orgs := newMockOrgRepo()
	orgs.users = users
	orgInvites := newMockOrgInviteRepo()

	keys := keyring.Derive([]byte("test-secret-at-least-32-bytes!!"))

	cfg := service.Config{
		CommonConfig: service.CommonConfig{
			AppName:    "TestApp",
			BaseURL:    "http://localhost:3000",
			SessionTTL: 30 * 24 * time.Hour,
			TokenTTL:   1 * time.Hour,
		},
		EnableEmailPassword:          true,
		EnableOAuth:                  true,
		EnableInvite:                 true,
		InviteTTL:                    7 * 24 * time.Hour,
		URLValidator:                 &port.URLValidator{AllowHTTP: true},
		TwoFactorCodeTTL:             time.Hour,
		TwoFactorBindingKey:          keys.TwoFactor,
		TwoFactorChallengeCookieName: "_2fa_challenge",
	}

	sessCfg := service.DefaultSessionConfig()
	sessCfg.Duration = 30 * 24 * time.Hour
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	twoFactorSvc := service.NewTwoFactorService(users, sessions, tokens, hasher, mailer, nil, cfg, sessSvc)
	authSvc := service.NewAuthService(users, sessions, tokens, hasher, gen, mailer, cfg, sessSvc, nil, twoFactorSvc)
	passSvc := service.NewPasswordService(users, tokens, hasher, gen, mailer, sessions, cfg)
	verifySvc := service.NewVerificationService(users, tokens, gen, mailer, cfg)
	inviteSvc := service.NewInviteService(users, sessions, nil, hasher, gen, mailer, cfg, sessSvc, twoFactorSvc)
	providers := newMockProviderAccountRepo()
	auditLogs := newMockAuditLogRepo()
	adminSvc := service.NewAdminService(users, sessions, providers, auditLogs, hasher, cfg, sessSvc)
	orgSvc := service.NewOrgService(orgs, users, sessions, &mockTxManager{}, service.OrgServiceConfig{
		MaxOrgsPerUser: 100,
		Logger:         nil,
	})
	orgInviteSvc := service.NewOrgInviteService(orgInvites, orgs, users, &mockTxManager{}, gen, &mockMailer{}, service.OrgInviteServiceConfig{
		MaxOrgsPerUser: 100,
		InviteTTL:      7 * 24 * time.Hour,
		BaseURL:        "http://localhost:3000",
		AppName:        "TestApp",
		URLValidator:   &port.URLValidator{AllowHTTP: true},
		Logger:         nil,
	})

	h := New(Services{
		Auth:      authSvc,
		Password:  passSvc,
		Session:   sessSvc,
		Verify:    verifySvc,
		Invite:    inviteSvc,
		Admin:     adminSvc,
		Org:       orgSvc,
		OrgInvite: orgInviteSvc,
		TwoFactor: twoFactorSvc,
		AuditLog:  auditLogs,
	})
	return &testHarness{handler: h, users: users, sessions: sessions, tokens: tokens, mailer: mailer, orgs: orgs, orgInvites: orgInvites, providers: providers, auditLogs: auditLogs, twoFactor: twoFactorSvc}
}
