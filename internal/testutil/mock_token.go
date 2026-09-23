package testutil

import (
	"context"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// MockTokenRepo stores verification tokens in memory for tests.
type MockTokenRepo struct {
	mu     sync.Mutex
	tokens map[string]*domain.VerificationToken
}

// NewMockTokenRepo returns an empty token repository.
func NewMockTokenRepo() *MockTokenRepo {
	return &MockTokenRepo{tokens: make(map[string]*domain.VerificationToken)}
}

// Create stores a token under its ID and hash.
func (m *MockTokenRepo) Create(_ context.Context, t *domain.VerificationToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.ID] = t
	m.tokens[t.TokenHash] = t
	return nil
}

// GetByHash returns the token with the given hash.
func (m *MockTokenRepo) GetByHash(_ context.Context, hash string) (*domain.VerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[hash]
	if !ok {
		return nil, nil
	}
	return t, nil
}

// MarkUsed records the current time on the token.
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

// MarkUsedIfUnused claims a token that has not been used.
func (m *MockTokenRepo) MarkUsedIfUnused(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok || t.UsedAt != nil {
		return false, nil
	}
	now := time.Now().UTC()
	t.UsedAt = &now
	return true, nil
}

// ConsumeIfValid claims a token when every input predicate matches.
func (m *MockTokenRepo) ConsumeIfValid(_ context.Context, input port.ConsumeTokenInput) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[input.ID]
	if !ok || t.TokenHash != input.TokenHash || t.UserID == nil || *t.UserID != input.UserID ||
		t.Type != input.Type || t.UsedAt != nil || !t.ExpiresAt.After(input.UsedAt) {
		return false, nil
	}
	usedAt := input.UsedAt
	t.UsedAt = &usedAt
	return true, nil
}

// GetByID returns the token with the given ID.
func (m *MockTokenRepo) GetByID(_ context.Context, id string) (*domain.VerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok {
		return nil, nil
	}
	return t, nil
}

// IncrementAttempts mirrors the guarded SQL attempt counter.
// MarkUsedIfUnderCap and UpdateForResend use the same lock and cap checks.
// SQL semantics: each checks its cap under the same lock that applies the
// change and reports whether it landed. Modelling them as unconditional writes
// would let tests pass while the real cap does nothing.
func (m *MockTokenRepo) IncrementAttempts(_ context.Context, id string, maxAttemptsPerChallenge int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok || t.Attempts >= maxAttemptsPerChallenge {
		return false, nil
	}
	t.Attempts++
	return true, nil
}

// MarkUsedIfUnderCap claims an unused token below its attempt cap.
func (m *MockTokenRepo) MarkUsedIfUnderCap(_ context.Context, id string, maxAttemptsPerChallenge int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok || t.UsedAt != nil || t.Attempts >= maxAttemptsPerChallenge {
		return false, nil
	}
	now := time.Now().UTC()
	t.UsedAt = &now
	return true, nil
}

// UpdateForResend rotates a challenge token below its resend and attempt caps.
func (m *MockTokenRepo) UpdateForResend(_ context.Context, id string, newHash string, newExpiresAt time.Time, newCreatedAt time.Time, maxRefreshesPerChallenge, maxAttemptsPerChallenge int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok || t.UsedAt != nil || t.ResendCount >= maxRefreshesPerChallenge || t.Attempts >= maxAttemptsPerChallenge {
		return false, nil
	}
	delete(m.tokens, t.TokenHash)
	t.TokenHash = newHash
	t.ExpiresAt = newExpiresAt
	t.CreatedAt = newCreatedAt
	t.ResendCount++
	m.tokens[newHash] = t
	return true, nil
}

// DeleteExpired is a no-op for this test repository.
func (m *MockTokenRepo) DeleteExpired(_ context.Context) error {
	return nil
}

// DeleteUnusedByUserAndType really deletes, matching sqlstore. It used to
// return nil without touching anything, which silently passed any test whose
// subject was the cleanup itself.
//
// Tokens are indexed under both their id and their hash, so a single row is
// two entries here; the predicate matches both, and deleting during a range is
// well defined in Go.
func (m *MockTokenRepo) DeleteUnusedByUserAndType(_ context.Context, userID string, tokenType domain.TokenType) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, t := range m.tokens {
		if t.UserID != nil && *t.UserID == userID && t.Type == tokenType && t.UsedAt == nil {
			delete(m.tokens, key)
		}
	}
	return nil
}

// GetLastByUserAndType returns the newest matching token.
func (m *MockTokenRepo) GetLastByUserAndType(_ context.Context, userID string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
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

// HasValidByUserAndType reports whether an unused matching token remains valid.
func (m *MockTokenRepo) HasValidByUserAndType(_ context.Context, userID string, tokenType domain.TokenType) (bool, error) {
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

// List returns each stored token once.
func (m *MockTokenRepo) List() []*domain.VerificationToken {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*domain.VerificationToken
	seen := make(map[string]bool)
	for _, t := range m.tokens {
		if t.ID != "" && !seen[t.ID] {
			result = append(result, t)
			seen[t.ID] = true
		}
	}
	return result
}

// GetLastVerificationCode extracts the code from the most recent test email.
func GetLastVerificationCode(mailer *MockMailer) string {
	if len(mailer.Calls) == 0 {
		return ""
	}
	call := mailer.Calls[len(mailer.Calls)-1]
	text := call.Text

	codeStart := -1
	for i, c := range text {
		if c == ':' && i+2 < len(text) && text[i+1] == ' ' {
			codeStart = i + 2
			break
		}
	}
	if codeStart == -1 {
		return ""
	}

	codeEnd := -1
	for i := codeStart; i < len(text); i++ {
		if text[i] == ' ' || text[i] == '(' || text[i] == '\n' || text[i] == '\r' {
			codeEnd = i
			break
		}
	}
	if codeEnd == -1 {
		codeEnd = len(text)
	}

	return text[codeStart:codeEnd]
}
