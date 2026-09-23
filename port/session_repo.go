package port

import (
	"context"
	"github.com/nazimdjebloun/go-auth/domain"
	"time"
)

// UpdateRefreshInput rotates a session's tokens on refresh. The
// implementation must find the session by OldRefreshHash, reject it if
// MaxLifetime (0 = no limit) or IdleTTL has elapsed, and otherwise
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
	IdleTTL        time.Duration // 0 = disabled
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

// SessionFilter narrows and orders session queries.
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
	OrderBy          SessionSortField
	OrderDirection   SortDirection
	Offset           int
	Limit            int
}

// SessionReader covers session lookups and listing — no mutation.
type SessionReader interface {
	GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	// GetByTokenHashWithUser returns a session together with its owning user
	// in a single query. AuthMiddleware runs on every authenticated request
	// and needs both, so this keeps that path at one round trip instead of a
	// lookup followed by a second one whose WHERE clause the first already
	// determined. Returns (nil, nil, nil) when no session matches.
	GetByTokenHashWithUser(ctx context.Context, tokenHash string) (*domain.Session, *domain.User, error)
	GetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error)
	GetByPreviousRefreshHash(ctx context.Context, hash string) (*domain.Session, error)
	LockAndGetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error)

	// ListByUserID returns a user's active sessions, paginated, plus a total count.
	ListByUserID(ctx context.Context, userID string, offset, limit int) ([]domain.Session, int, error)
	// ListAllByUserID returns all of a user's active sessions (no pagination).
	ListAllByUserID(ctx context.Context, userID string) ([]domain.Session, error)
	// ListAll returns a page of active sessions across all users (admin). It
	// does not count the full set — use CountAll for the total.
	ListAll(ctx context.Context, filter SessionFilter) ([]domain.Session, error)
	// CountAll returns how many sessions match filter (Offset/Limit ignored).
	CountAll(ctx context.Context, filter SessionFilter) (int, error)
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
