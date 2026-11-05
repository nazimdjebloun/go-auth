package testutil

import (
	"context"

	"github.com/nazimdjebloun/go-auth/domain"
)

// LockByID participates in mock transaction snapshots. SQL fixtures exercise
// the real row-lock lifetime and ordering.
func (m *MockSessionRepo) LockByID(ctx context.Context, id string) (*domain.Session, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	session := m.byID[id]
	if session == nil {
		return nil, nil
	}
	snapshot := *session
	return &snapshot, nil
}
