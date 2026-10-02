package testutil

import (
	"context"
	"sync"

	"github.com/nazimdjebloun/go-auth/domain"
)

// MockProviderAccountRepo stores OAuth account links in memory for tests.
type MockProviderAccountRepo struct {
	mu       sync.Mutex
	accounts map[string]*domain.ProviderAccount
}

// NewMockProviderAccountRepo returns an empty provider-account repository.
func NewMockProviderAccountRepo() *MockProviderAccountRepo {
	return &MockProviderAccountRepo{accounts: make(map[string]*domain.ProviderAccount)}
}

// Create stores a provider account.
func (m *MockProviderAccountRepo) Create(ctx context.Context, pa *domain.ProviderAccount) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accounts[pa.ID] = pa
	return nil
}

// GetByProvider returns a matching provider account.
func (m *MockProviderAccountRepo) GetByProvider(ctx context.Context, provider, providerUserID string) (*domain.ProviderAccount, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, pa := range m.accounts {
		if pa.Provider == provider && pa.ProviderUserID == providerUserID {
			return pa, nil
		}
	}
	return nil, nil
}

// ListByUserID returns a user's provider accounts.
func (m *MockProviderAccountRepo) ListByUserID(ctx context.Context, userID string) ([]domain.ProviderAccount, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []domain.ProviderAccount
	for _, pa := range m.accounts {
		if pa.UserID == userID {
			res = append(res, *pa)
		}
	}
	return res, nil
}

// Delete removes a user's provider account.
func (m *MockProviderAccountRepo) Delete(ctx context.Context, userID, provider string) error {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, pa := range m.accounts {
		if pa.UserID == userID && pa.Provider == provider {
			delete(m.accounts, id)
		}
	}
	return nil
}

// LockByUserID enlists the repository in mock rollback. It does not simulate
// SQL row locks; concurrency guarantees are tested with real SQL fixtures.
func (m *MockProviderAccountRepo) LockByUserID(ctx context.Context, _ string) error {
	recordMockTx(ctx, m)
	return nil
}
