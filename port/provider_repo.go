package port

import (
	"context"
	"github.com/nazimdjebloun/go-auth/domain"
)

// ProviderAccountRepository stores OAuth account links.
type ProviderAccountRepository interface {
	Create(ctx context.Context, pa *domain.ProviderAccount) error
	GetByProvider(ctx context.Context, provider, providerUserID string) (*domain.ProviderAccount, error)
	ListByUserID(ctx context.Context, userID string) ([]domain.ProviderAccount, error)
	Delete(ctx context.Context, userID, provider string) error
	// LockByUserID takes the write locks on every provider_accounts row the
	// user owns, via a self-assigning UPDATE — the portable equivalent of
	// SELECT ... FOR UPDATE (SQLite has no FOR UPDATE syntax). Call it first
	// inside a transaction so concurrent guard-then-delete sequences for the
	// same user (e.g. two parallel Unlink requests) serialize instead of both
	// observing the same pre-delete provider set.
	LockByUserID(ctx context.Context, userID string) error
}
