package testutil

import (
	"context"
	"sync"

	"github.com/nazimdjebloun/go-auth/domain"
)

type MockProviderAccountRepo struct {
	mu       sync.Mutex
	accounts map[string]*domain.ProviderAccount
}

func NewMockProviderAccountRepo() *MockProviderAccountRepo {
	return &MockProviderAccountRepo{accounts: make(map[string]*domain.ProviderAccount)}
}

func (m *MockProviderAccountRepo) Create(_ context.Context, pa *domain.ProviderAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accounts[pa.ID] = pa
	return nil
}

func (m *MockProviderAccountRepo) GetByProvider(_ context.Context, provider, providerUserID string) (*domain.ProviderAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, pa := range m.accounts {
		if pa.Provider == provider && pa.ProviderUserID == providerUserID {
			return pa, nil
		}
	}
	return nil, nil
}

func (m *MockProviderAccountRepo) ListByUserID(_ context.Context, userID string) ([]domain.ProviderAccount, error) {
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

func (m *MockProviderAccountRepo) Delete(_ context.Context, userID, provider string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, pa := range m.accounts {
		if pa.UserID == userID && pa.Provider == provider {
			delete(m.accounts, id)
			break
		}
	}
	return nil
}
