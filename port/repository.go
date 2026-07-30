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
	UpdateLastLoginAt(ctx context.Context, userID string, t time.Time) error
}

type UpdateRefreshInput struct {
	OldRefreshHash string
	NewTokenHash   string
	NewRefreshHash string
	NewExpiresAt   time.Time
	RotatedAt      time.Time
	MaxLifetime    time.Duration // 0 = disabled
	GraceWindow    time.Duration
}

type SessionFilter struct {
	UserID *string
	Offset int
	Limit  int
}

type SessionRepository interface {
	Create(ctx context.Context, s *domain.Session) error
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	GetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error)
	GetByPreviousRefreshHash(ctx context.Context, hash string) (*domain.Session, error)
	LockAndGetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error)
	ListByUserID(ctx context.Context, userID string, offset, limit int) ([]domain.Session, int, error)
	ListAllSessions(ctx context.Context, filter SessionFilter) ([]domain.Session, int, error)
	Delete(ctx context.Context, tokenHash string) error
	DeleteByID(ctx context.Context, id string) error
	DeleteAllForUser(ctx context.Context, userID string) error
	DeleteAllForUserExcept(ctx context.Context, userID string, exceptSessionID string) error
	DeleteExpired(ctx context.Context) error
	UpdateLastActiveAt(ctx context.Context, tokenHash string) error
	UpdateRefreshToken(ctx context.Context, input UpdateRefreshInput) (*domain.Session, error)
	Revoke(ctx context.Context, id string) error

	UpdateActiveOrgRoleForUser(ctx context.Context, userID, orgID string, newRole domain.OrgRole) error
	ClearActiveOrgForUser(ctx context.Context, userID, orgID string) error
	ClearActiveOrgForAllMembers(ctx context.Context, orgID string) error
	SetActiveOrg(ctx context.Context, sessionID, orgID string, role domain.OrgRole) error
}

type TokenRepository interface {
	Create(ctx context.Context, t *domain.VerificationToken) error
	GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error)
	HasValidByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) (bool, error)
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
	// ClaimInvite atomically sets status to 'accepted' only if currently 'pending'.
	// Returns true if the invite was claimed, false if already accepted/revoked/expired.
	ClaimInvite(ctx context.Context, code string, acceptedAt time.Time) (bool, error)
}

type ProviderAccountRepository interface {
	Create(ctx context.Context, pa *domain.ProviderAccount) error
	GetByProvider(ctx context.Context, provider, providerUserID string) (*domain.ProviderAccount, error)
	ListByUserID(ctx context.Context, userID string) ([]domain.ProviderAccount, error)
	Delete(ctx context.Context, userID, provider string) error
}

type OrgRepository interface {
	Create(ctx context.Context, org *domain.Organization) error
	GetByID(ctx context.Context, id string) (*domain.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*domain.Organization, error)
	Update(ctx context.Context, org *domain.Organization) error
	Delete(ctx context.Context, id string) error

	AddMember(ctx context.Context, member *domain.OrgMember) error
	RemoveMember(ctx context.Context, orgID, userID string) error
	UpdateMemberRole(ctx context.Context, orgID, userID string, role domain.OrgRole) error
	GetMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error)
	ListMembers(ctx context.Context, orgID string, offset, limit int) ([]domain.OrgMemberDetail, int, error)
	ListUserOrgs(ctx context.Context, userID string) ([]domain.Organization, error)

	IncrementUserOrgOwnerCount(ctx context.Context, userID string, maxOrgs int) error
	DecrementUserOrgOwnerCount(ctx context.Context, userID string) error
	IncrementOrgMemberCount(ctx context.Context, orgID string, maxMembers int) error
	DecrementOrgMemberCount(ctx context.Context, orgID string) error
	TryDecrementOrgOwnerCount(ctx context.Context, orgID string) error
	IncrementOrgOwnerCount(ctx context.Context, orgID string) error
	DecrementOwnerCountForOrgOwners(ctx context.Context, orgID string) error
}

type OrgInviteRepository interface {
	Create(ctx context.Context, invite *domain.OrgInvite) error
	GetByID(ctx context.Context, id string) (*domain.OrgInvite, error)
	GetByCodeHash(ctx context.Context, codeHash string) (*domain.OrgInvite, error)
	ListByOrgID(ctx context.Context, orgID string) ([]domain.OrgInvite, error)
	Update(ctx context.Context, invite *domain.OrgInvite) error
	Delete(ctx context.Context, id string) error
	ClaimInvite(ctx context.Context, id string) (bool, error)
}
