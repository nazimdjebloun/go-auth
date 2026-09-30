package testutil

import (
	"context"

	"github.com/nazimdjebloun/go-auth/port"
)

// ConsumeIfValidUnderCap mirrors the single guarded SQL update.
func (m *MockTokenRepo) ConsumeIfValidUnderCap(_ context.Context, input port.ConsumeTokenInput, maxAttempts int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token := m.tokens[input.ID]
	if token == nil || token.TokenHash != input.TokenHash ||
		token.UserID == nil || *token.UserID != input.UserID || token.Type != input.Type ||
		token.UsedAt != nil || !token.ExpiresAt.After(input.UsedAt) || token.Attempts >= maxAttempts {
		return false, nil
	}
	token.UsedAt = &input.UsedAt
	return true, nil
}
