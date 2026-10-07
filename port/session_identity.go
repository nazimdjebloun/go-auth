package port

import (
	"context"

	"github.com/nazimdjebloun/go-auth/domain"
)

// SessionIdentityReader reloads assurance for direct actor-authorized operations.
type SessionIdentityReader interface {
	GetByID(context.Context, string) (*domain.Session, error)
}
