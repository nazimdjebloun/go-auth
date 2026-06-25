package port

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

type UserFilter struct {
	Email          *string
	Role           *domain.Role
	IsBanned       *bool
	IsVerified     *bool
	Search         *string
	OrderBy        string // "created_at" or "updated_at"
	OrderDirection string // "asc" or "desc"
	Offset         int
	Limit          int // 0 means unlimited
}

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter UserFilter) ([]domain.User, int, error)
	SetPasswordAndVerify(ctx context.Context, userID string, passwordHash string, tokenID string) error
	SetBanStatus(ctx context.Context, userID string, isBanned bool, bannedAt *time.Time, updatedAt time.Time) error
}

type SessionRepository interface {
	Create(ctx context.Context, s *domain.Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	ListByUserID(ctx context.Context, userID string) ([]domain.Session, error)
	Delete(ctx context.Context, tokenHash string) error
	DeleteByID(ctx context.Context, id string) error
	DeleteAllForUser(ctx context.Context, userID string) error
	DeleteAllForUserExcept(ctx context.Context, userID string, exceptSessionID string) error
	DeleteExpired(ctx context.Context) error
	UpdateLastActiveAt(ctx context.Context, tokenHash string) error
}

type TokenRepository interface {
	Create(ctx context.Context, t *domain.VerificationToken) error
	GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error)
	MarkUsed(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
	DeleteUnusedByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) error
}

type InviteFilter struct {
	Search *string
	Status *string
	Offset int
	Limit  int
}

type InviteRepository interface {
	Create(ctx context.Context, invite *domain.Invite) error
	GetByID(ctx context.Context, id string) (*domain.Invite, error)
	GetByCode(ctx context.Context, code string) (*domain.Invite, error)
	GetByEmail(ctx context.Context, email string) (*domain.Invite, error)
	List(ctx context.Context, filter InviteFilter) ([]domain.Invite, int, error)
	Update(ctx context.Context, invite *domain.Invite) error
	Delete(ctx context.Context, id string) error
}

type ProviderAccountRepository interface {
	Create(ctx context.Context, pa *domain.ProviderAccount) error
	GetByProvider(ctx context.Context, provider, providerUserID string) (*domain.ProviderAccount, error)
	ListByUserID(ctx context.Context, userID string) ([]domain.ProviderAccount, error)
	Delete(ctx context.Context, userID, provider string) error
}
