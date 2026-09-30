package testutil

import (
	"context"

	"github.com/nazimdjebloun/go-auth/domain"
)

// GetByIDForUpdate supports sequential mock transactions. Concurrency guarantees
// are exercised against the SQL repositories.
func (m *MockUserRepo) GetByIDForUpdate(ctx context.Context, id string) (*domain.User, error) {
	return m.GetByID(ctx, id)
}
