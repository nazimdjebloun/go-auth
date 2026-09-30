package handler

import (
	"context"

	"github.com/nazimdjebloun/go-auth/domain"
)

func (m *mockUserRepo) GetByIDForUpdate(ctx context.Context, id string) (*domain.User, error) {
	return m.GetByID(ctx, id)
}
