// This file declares go-auth's storage interfaces — UserRepository,
// SessionRepository, TokenRepository, InviteRepository, OrgRepository,
// OrgInviteRepository, ProviderAccountRepository, AuditLogRepository — each
// implemented against SQL by the (internal) sqlstore package. Implement one
// of these to back a repository with something other than SQL; there's no
// embeddable base, so a replacement implements every method on the
// interface it's swapping in for.
package port

import (
	"context"
	"encoding/json"
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
	SetTwoFactorEnabled(ctx context.Context, userID string, enabled bool, updatedAt time.Time) error
}

// UpdateRefreshInput rotates a session's tokens on refresh. The
// implementation must find the session by OldRefreshHash, reject it if
// MaxLifetime (0 = no limit) has elapsed since creation, and otherwise
// atomically: move the current refresh hash to PreviousRefreshHash, set the
// new token/refresh hashes and NewExpiresAt, and stamp RotatedAt.
// GraceWindow is how long OldRefreshHash — now the previous hash — is still
// accepted as a courtesy for a request that raced the rotation (returning
// the *same* rotated session rather than treating it as reuse); after the
// window elapses, presenting a previous hash again must be treated as
// token-reuse detection and revoke the session, since a rotated token being
// reused past the grace window means it leaked.
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
	// Create persists a new session.
	Create(ctx context.Context, s *domain.Session) error

	// ── Lookups ─────────────────────────────────────────────────────────────
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	GetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error)
	GetByPreviousRefreshHash(ctx context.Context, hash string) (*domain.Session, error)
	LockAndGetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error)

	// ── Listing ─────────────────────────────────────────────────────────────
	// ListByUserID returns a user's active sessions, paginated, plus a total count.
	ListByUserID(ctx context.Context, userID string, offset, limit int) ([]domain.Session, int, error)
	// ListAllByUserID returns all of a user's active sessions (no pagination).
	ListAllByUserID(ctx context.Context, userID string) ([]domain.Session, error)
	// ListAll returns active sessions across all users, optionally filtered (admin).
	ListAll(ctx context.Context, filter SessionFilter) ([]domain.Session, int, error)

	// ── Delete (hard delete, no ownership check) ─────────────────────────────
	// Delete removes a session by its access-token hash (logout path).
	Delete(ctx context.Context, tokenHash string) error
	// DeleteByID removes a session by its id.
	DeleteByID(ctx context.Context, id string) error
	// DeleteAllForUser removes every session belonging to a user.
	DeleteAllForUser(ctx context.Context, userID string) error
	// DeleteAllForUserExcept removes all of a user's sessions except one.
	DeleteAllForUserExcept(ctx context.Context, userID string, exceptSessionID string) error
	// DeleteExpired removes sessions past their refresh expiry (maintenance).
	DeleteExpired(ctx context.Context) error

	// ── Revoke (user-scoped delete, ownership enforced in SQL) ───────────────
	// RevokeByIDForUser removes one session only if it belongs to userID.
	// Returns false if the session is missing or belongs to someone else.
	RevokeByIDForUser(ctx context.Context, id, userID string) (bool, error)
	// RevokeManyForUser removes the given sessions only if they belong to userID.
	// Returns the number of sessions actually removed.
	RevokeManyForUser(ctx context.Context, ids []string, userID string) (int, error)

	// ── State updates ────────────────────────────────────────────────────────
	UpdateLastActiveAt(ctx context.Context, tokenHash string) error
	UpdateRefreshToken(ctx context.Context, input UpdateRefreshInput) (*domain.Session, error)

	// ── Active org ───────────────────────────────────────────────────────────
	UpdateActiveOrgRoleForUser(ctx context.Context, userID, orgID string, newRole domain.OrgRole) error
	ClearActiveOrgForUser(ctx context.Context, userID, orgID string) error
	ClearActiveOrgForAllMembers(ctx context.Context, orgID string) error
	ClearActiveOrg(ctx context.Context, sessionID string) error
	SetActiveOrg(ctx context.Context, sessionID, orgID string, role domain.OrgRole) error
}

type TokenRepository interface {
	Create(ctx context.Context, t *domain.VerificationToken) error
	GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error)
	GetByID(ctx context.Context, id string) (*domain.VerificationToken, error)
	GetLastByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) (*domain.VerificationToken, error)
	HasValidByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) (bool, error)
	MarkUsed(ctx context.Context, id string) error
	DeleteExpired(ctx context.Context) error
	DeleteUnusedByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) error

	// IncrementAttempts, MarkUsedIfUnderCap and UpdateForResend are guarded
	// updates: each applies its cap in the WHERE clause and reports whether the
	// row was actually touched. Read-then-write would be a TOCTOU — concurrent
	// requests all observe the same pre-increment count and all pass the cap
	// check before any write lands. Returning bool rather than the new count
	// also keeps them driver-portable: MySQL has no UPDATE...RETURNING.
	IncrementAttempts(ctx context.Context, id string, maxAttemptsPerChallenge int) (bool, error)
	MarkUsedIfUnderCap(ctx context.Context, id string, maxAttemptsPerChallenge int) (bool, error)
	UpdateForResend(ctx context.Context, id string, newHash string, newExpiresAt time.Time, maxRefreshesPerChallenge, maxAttemptsPerChallenge int) (bool, error)
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

type AuditLogFilter struct {
	Type         *string
	ActorID      *string
	TargetUserID *string
	SessionID    *string
	OrgID        *string
	Success      *bool
	Search       *string
	FromDate     *time.Time
	ToDate       *time.Time
	Offset       int
	Limit        int
}

type AuditLogEntry struct {
	ID            string
	Type          string
	Severity      string
	Success       bool
	ActorID       *string
	TargetUserID  *string
	SessionID     *string
	OrgID         *string
	IP            string
	UserAgent     string
	ParsedUA      json.RawMessage
	RequestID     string
	CorrelationID string
	Metadata      json.RawMessage
	CreatedAt     time.Time
}

type AuditLogRepository interface {
	List(ctx context.Context, filter AuditLogFilter) ([]AuditLogEntry, int, error)
	GetByID(ctx context.Context, id string) (*AuditLogEntry, error)
}
