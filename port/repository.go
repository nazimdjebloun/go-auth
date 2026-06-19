package port

import (
	"context"
	"github.com/nazimdjebloun/go-auth/domain"
)

type UserFilter struct {
	Email    *string
	Role     *domain.Role
	IsBanned *bool
	IsVerified *bool
	Offset   int
	Limit    int
}

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter UserFilter) ([]domain.User, int, error)
}

type SessionRepository interface {
	Create(ctx context.Context, s *domain.Session) error
	GetByTokenHash(ctx context.Context, hash string) (*domain.Session, error)
	ListByUserID(ctx context.Context, userID string) ([]domain.Session, error)
	Revoke(ctx context.Context, id string) error
	RevokeAllForUser(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) error
}

type TokenRepository interface {
	Create(ctx context.Context, t *domain.VerificationToken) error
	GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error)
	MarkUsed(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
}

type InviteRepository interface {
	Create(ctx context.Context, invite *domain.Invite) error
	GetByID(ctx context.Context, id string) (*domain.Invite, error)
	GetByCode(ctx context.Context, code string) (*domain.Invite, error)
	GetByEmail(ctx context.Context, email string) (*domain.Invite, error)
	List(ctx context.Context, offset, limit int) ([]domain.Invite, int, error)
	Update(ctx context.Context, invite *domain.Invite) error
}
