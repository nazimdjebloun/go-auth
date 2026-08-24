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
	"errors"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// ErrDuplicateKey is returned by a repository's Create method when the
// underlying store rejects the write with a unique-constraint violation —
// e.g. two requests racing to register the same email, link the same
// provider account, or create the same org slug. It's a storage-outcome
// contract, not a sqlstore-specific detail, so it lives here rather than in
// sqlstore: service depends on port and domain only, and checking
// errors.Is(err, port.ErrDuplicateKey) lets it react to the race without
// importing sqlstore or knowing which driver produced the error. Callers
// translate it to the appropriate domain sentinel (domain.ErrEmailAlreadyExists,
// domain.ErrOrgSlugExists, domain.ErrProviderAccountExists, ...).
var ErrDuplicateKey = errors.New("port: duplicate key")

type UserFilter struct {
	// IDs matches any of the listed user IDs ("IN (...)") — a batch lookup,
	// not a per-admin-question filter like the fields below it. Used to
	// resolve a page of IDs (e.g. audit log actor/target IDs) to users in
	// one round trip instead of one query per ID.
	IDs              []string
	Email            *string
	Role             *domain.Role
	IsBanned         *bool
	IsVerified       *bool
	TwoFactorEnabled *bool
	// NeverLoggedIn and LastLoginBefore are independent, composable dormancy
	// filters, not one merged "inactive since" flag: "registered, never
	// logged in since" and "logged in before, gone dormant since" are
	// different admin questions.
	NeverLoggedIn   *bool      // true: last_login_at IS NULL
	LastLoginBefore *time.Time // last_login_at < X, excluding NULLs
	// CreatedAfter/CreatedBefore scope List/CountByDay to a registration
	// date range — used by the admin registrations-over-time trend.
	CreatedAfter   *time.Time
	CreatedBefore  *time.Time
	Search         *string
	OrderBy        string // "created_at" or "updated_at"
	OrderDirection string // "asc" or "desc"
	Offset         int
	Limit          int // 0 means unlimited
}

// DailyCount is one bucket of a day-by-day aggregate — the shape both
// UserRepository.CountByDay and AuditLogRepository.CountByDay return, for
// building a registrations-over-time chart or a GitHub-style login heatmap
// without pulling raw rows client-side.
type DailyCount struct {
	Date  time.Time `json:"date"` // truncated to day, UTC
	Count int       `json:"count"`
}

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter UserFilter) ([]domain.User, int, error)
	// CountByDay returns registrations per day matching filter (Offset/Limit
	// on filter are ignored — the result is naturally bounded by the date
	// range in filter.CreatedAfter/CreatedBefore).
	CountByDay(ctx context.Context, filter UserFilter) ([]DailyCount, error)
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

// ErrRefreshTokenReused is UpdateRefreshToken's error for the theft-suspected
// case described above: a previous-generation refresh token presented past
// the grace window. The implementation has already revoked the compromised
// session by the time this returns — UserID/SessionID identify it so the
// caller (which owns the audit publisher, not the repository) can record
// the event. Callers that only care about the client-facing outcome can
// still match domain.ErrSessionRevoked via errors.Is, since this wraps it.
type ErrRefreshTokenReused struct {
	UserID    string
	SessionID string
}

func (e *ErrRefreshTokenReused) Error() string {
	return "port: refresh token reused past grace window (session " + e.SessionID + " revoked)"
}

type SessionFilter struct {
	UserID *string
	// IP matches sessions.ip_address exactly.
	IP *string
	// Search substring-matches ip_address OR user_agent — the free-text box
	// on an admin session search ("find the session from this device/IP").
	Search           *string
	CreatedAfter     *time.Time
	CreatedBefore    *time.Time
	ExpiresAfter     *time.Time
	ExpiresBefore    *time.Time
	LastActiveAfter  *time.Time
	LastActiveBefore *time.Time
	OrderBy          string // "created_at" (default), "expires_at", "last_active_at"
	OrderDirection   string // "asc" or "desc"
	Offset           int
	Limit            int
}

// SessionReader covers session lookups and listing — no mutation.
type SessionReader interface {
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	GetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error)
	GetByPreviousRefreshHash(ctx context.Context, hash string) (*domain.Session, error)
	LockAndGetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error)

	// ListByUserID returns a user's active sessions, paginated, plus a total count.
	ListByUserID(ctx context.Context, userID string, offset, limit int) ([]domain.Session, int, error)
	// ListAllByUserID returns all of a user's active sessions (no pagination).
	ListAllByUserID(ctx context.Context, userID string) ([]domain.Session, error)
	// ListAll returns active sessions across all users, optionally filtered (admin).
	ListAll(ctx context.Context, filter SessionFilter) ([]domain.Session, int, error)
}

// SessionWriter covers session creation and in-place field updates —
// everything short of deleting/revoking a session.
type SessionWriter interface {
	// Create persists a new session.
	Create(ctx context.Context, s *domain.Session) error
	UpdateLastActiveAt(ctx context.Context, tokenHash string) error
	UpdateRefreshToken(ctx context.Context, input UpdateRefreshInput) (*domain.Session, error)
}

// SessionRevoker covers every way a session stops being valid: hard deletes
// (no ownership check — logout/maintenance paths) and user-scoped revokes
// (ownership enforced in SQL — a user can only revoke their own sessions).
type SessionRevoker interface {
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

	// RevokeByIDForUser removes one session only if it belongs to userID.
	// Returns false if the session is missing or belongs to someone else.
	RevokeByIDForUser(ctx context.Context, id, userID string) (bool, error)
	// RevokeManyForUser removes the given sessions only if they belong to userID.
	// Returns the number of sessions actually removed.
	RevokeManyForUser(ctx context.Context, ids []string, userID string) (int, error)
}

// ActiveOrgSessionStore covers a session's "active org" pointer — which
// org, if any, a session is currently scoped to.
type ActiveOrgSessionStore interface {
	UpdateActiveOrgRoleForUser(ctx context.Context, userID, orgID string, newRole domain.OrgRole) error
	ClearActiveOrgForUser(ctx context.Context, userID, orgID string) error
	ClearActiveOrgForAllMembers(ctx context.Context, orgID string) error
	ClearActiveOrg(ctx context.Context, sessionID string) error
	SetActiveOrg(ctx context.Context, sessionID, orgID string, role domain.OrgRole) error
}

// SessionRepository composes the four facets above for sqlstore and any
// consumer that wants the full session contract in one implementation.
// Services that only need a slice (e.g. only revoking, or only the active-org
// pointer) should depend on that slice's interface directly instead — see
// service/password.go and service/org.go for examples.
type SessionRepository interface {
	SessionReader
	SessionWriter
	SessionRevoker
	ActiveOrgSessionStore
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
	Search         *string
	Status         *string
	OrderBy        string // "created_at" (default), "expires_at", "email", "status"
	OrderDirection string // "asc" or "desc"
	Offset         int
	Limit          int
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

// OrgMemberFilter narrows and orders OrgCRUD.ListMembers within one org.
// orgID stays a separate positional argument on ListMembers rather than a
// field here — it's a hard scoping boundary, not an optional filter.
type OrgMemberFilter struct {
	Role           *domain.OrgRole
	Search         *string // matches member's name or email
	OrderBy        string  // "joined_at" (default), "role", "name", or "email"
	OrderDirection string  // "asc" or "desc"
	Offset         int
	Limit          int // 0 means unlimited
}

// UserOrgFilter narrows and orders OrgCRUD.ListUserOrgs for one user.
type UserOrgFilter struct {
	Search         *string // matches org name or slug
	OrderBy        string  // "name" (default), "created_at", or "member_count"
	OrderDirection string  // "asc" or "desc"
	Offset         int
	Limit          int // 0 means unlimited
}

// OrgFilter narrows and orders OrgCRUD.List — the platform-admin, cross-org
// listing (as opposed to UserOrgFilter, which is scoped to one user's
// memberships).
type OrgFilter struct {
	Search         *string // matches org name or slug
	CreatedAfter   *time.Time
	CreatedBefore  *time.Time
	OrderBy        string // "name" (default), "created_at", or "member_count"
	OrderDirection string // "asc" or "desc"
	Offset         int
	Limit          int // 0 means unlimited
}

// OrgCRUD covers organization and membership records themselves — creating,
// reading, updating, and deleting orgs and their members.
type OrgCRUD interface {
	Create(ctx context.Context, org *domain.Organization) error
	GetByID(ctx context.Context, id string) (*domain.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*domain.Organization, error)
	Update(ctx context.Context, org *domain.Organization) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, filter OrgFilter) ([]domain.Organization, int, error)

	AddMember(ctx context.Context, member *domain.OrgMember) error
	RemoveMember(ctx context.Context, orgID, userID string) error
	UpdateMemberRole(ctx context.Context, orgID, userID string, role domain.OrgRole) error
	GetMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error)
	ListMembers(ctx context.Context, orgID string, filter OrgMemberFilter) ([]domain.OrgMemberDetail, int, error)
	ListUserOrgs(ctx context.Context, userID string, filter UserOrgFilter) ([]domain.Organization, int, error)
}

// OrgLimitCounters maintains the denormalized owner/member counts that back
// SecurityConfig's org limits (max orgs owned per user, max members per
// org) — invariant-maintenance for that feature, not core org CRUD. Each
// Increment enforces its cap atomically in SQL (guarded update, not
// read-then-write) and returns an error if the cap is already reached.
type OrgLimitCounters interface {
	IncrementUserOrgOwnerCount(ctx context.Context, userID string, maxOrgs int) error
	DecrementUserOrgOwnerCount(ctx context.Context, userID string) error
	IncrementOrgMemberCount(ctx context.Context, orgID string, maxMembers int) error
	DecrementOrgMemberCount(ctx context.Context, orgID string) error
	TryDecrementOrgOwnerCount(ctx context.Context, orgID string) error
	IncrementOrgOwnerCount(ctx context.Context, orgID string) error
	DecrementOwnerCountForOrgOwners(ctx context.Context, orgID string) error
}

// OrgRepository composes the two facets above for sqlstore and any consumer
// that wants the full org contract in one implementation.
type OrgRepository interface {
	OrgCRUD
	OrgLimitCounters
}

// OrgInviteFilter narrows and orders OrgInviteRepository.ListByOrgID for one
// org. Status is derived from ExpiresAt vs the query time, not a stored
// column — there is no persisted invite status.
type OrgInviteFilter struct {
	Role           *domain.OrgRole
	Status         *string // "pending" or "expired"; nil means both
	Search         *string // matches invite email
	OrderBy        string  // "created_at" (default), "expires_at", "email", "role"
	OrderDirection string  // "asc" or "desc"
	Offset         int
	Limit          int // 0 means unlimited
}

type OrgInviteRepository interface {
	Create(ctx context.Context, invite *domain.OrgInvite) error
	GetByID(ctx context.Context, id string) (*domain.OrgInvite, error)
	GetByCodeHash(ctx context.Context, codeHash string) (*domain.OrgInvite, error)
	ListByOrgID(ctx context.Context, orgID string, filter OrgInviteFilter) ([]domain.OrgInvite, int, error)
	Update(ctx context.Context, invite *domain.OrgInvite) error
	Delete(ctx context.Context, id string) error
	ClaimInvite(ctx context.Context, id string) (bool, error)
}

type AuditLogFilter struct {
	// Types matches any of the listed event types ("IN (...)"); nil/empty
	// means no filter. A single-element slice is the old single-Type filter.
	Types        []string
	ActorID      *string
	TargetUserID *string
	SessionID    *string
	OrgID        *string
	// DeviceType matches parsed_ua's deviceType field exactly — "mobile",
	// "desktop", "tablet", or "bot" (see domain.ParseUserAgent).
	DeviceType *string
	// IP matches the ip column exactly. Search below still substring-matches
	// it too, for a fuzzy "which of these events came from that address"
	// lookup without knowing the exact stored value.
	IP      *string
	Success *bool
	// Search substring-matches metadata, user_agent, ip, and event_type —
	// broader than any single field filter, for a general free-text box.
	Search   *string
	FromDate *time.Time
	ToDate   *time.Time
	Offset   int
	Limit    int
}

// AuditLogEntry had no JSON tags until this comment's change — every field
// marshaled under its bare Go name ("ActorID", "CreatedAt", ...), not the
// camelCase the docs and the dashboard client always assumed. Pre-release,
// so fixing the mismatch outright rather than carrying it forward.
type AuditLogEntry struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	Severity      string          `json:"severity"`
	Success       bool            `json:"success"`
	ActorID       *string         `json:"actorId,omitempty"`
	TargetUserID  *string         `json:"targetUserId,omitempty"`
	SessionID     *string         `json:"sessionId,omitempty"`
	OrgID         *string         `json:"orgId,omitempty"`
	IP            string          `json:"ip,omitempty"`
	UserAgent     string          `json:"userAgent,omitempty"`
	ParsedUA      json.RawMessage `json:"parsedUA,omitempty"`
	RequestID     string          `json:"requestId,omitempty"`
	CorrelationID string          `json:"correlationId,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
}

type AuditLogRepository interface {
	List(ctx context.Context, filter AuditLogFilter) ([]AuditLogEntry, int, error)
	GetByID(ctx context.Context, id string) (*AuditLogEntry, error)
	// CountByDay returns event counts per day matching filter (Offset/Limit
	// on filter are ignored, same reasoning as UserRepository.CountByDay).
	CountByDay(ctx context.Context, filter AuditLogFilter) ([]DailyCount, error)
}
