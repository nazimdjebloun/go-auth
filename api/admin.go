package api

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// AdminAuditLogEntry adds resolved actor/target emails to a raw audit row —
// the row itself only stores IDs, and an admin reading a log wants to know
// *who*, not just a UUID. Both are nil if the corresponding *_id is nil, or
// if that user no longer exists (deleted since the event was recorded) —
// the row's IDs are the durable record either way.
type AdminAuditLogEntry struct {
	AuditLogEntry
	ActorEmail  *string `json:"actorEmail,omitempty"`
	TargetEmail *string `json:"targetEmail,omitempty"`
}

// AdminListAuditLogsInput scopes an audit-log query. ActorID is the calling
// admin (for requireAdmin), distinct from EventActorID/EventActorEmail,
// which filter the logged events themselves.
type AdminListAuditLogsInput struct {
	ActorID        string
	ActorSessionID string `json:"-"`

	EventTypes []string
	// EventActorID/EventActorEmail filter by who performed the logged
	// action. If both are set, EventActorEmail wins — it's resolved to a
	// user ID first and that replaces EventActorID.
	EventActorID    *string
	EventActorEmail *string
	// TargetUserID/TargetEmail filter by who the logged action was done
	// to, same email-wins-if-both rule as the actor pair above.
	TargetUserID *string
	TargetEmail  *string
	SessionID    *string
	OrgID        *string
	DeviceType   *string
	IP           *string
	Success      *bool
	Search       *string
	FromDate     *time.Time
	ToDate       *time.Time
	Offset       int
	Limit        int
}

// AdminListAuditLogsResult contains audit entries and the matching total.
type AdminListAuditLogsResult struct {
	Events []AdminAuditLogEntry `json:"events"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}

// AdminListSessionsInput scopes an admin-wide session search — every filter
// beyond ActorID is optional and composable (e.g. UserID + IP together).
type AdminListSessionsInput struct {
	ActorID          string
	ActorSessionID   string `json:"-"`
	UserID           *string
	IP               *string
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

// AdminListSessionsResult contains sessions and the matching total.
type AdminListSessionsResult struct {
	Sessions []domain.Session `json:"sessions"`
	Limit    int              `json:"limit"`
	Offset   int              `json:"offset"`
}

// AdminListUserSessionsInput contains pagination for a user's sessions.
type AdminListUserSessionsInput struct {
	ActorID        string // the admin performing this call
	ActorSessionID string `json:"-"`
	UserID         string
	Offset         int
	Limit          int
}

// AdminListUsersInput contains administrator user filters.
type AdminListUsersInput struct {
	AppRoleID        *string `json:"appRoleId,omitempty"`
	ActorID          string  // the admin performing this call
	ActorSessionID   string  `json:"-"`
	Offset           int
	Limit            int // default 20, max 100
	Email            *string
	Role             *domain.Role
	IsBanned         *bool
	IsVerified       *bool
	TwoFactorEnabled *bool
	// NeverLoggedIn and LastLoginBefore are independent dormancy filters —
	// see port.UserFilter's doc comment for why they're kept separate.
	NeverLoggedIn   *bool
	LastLoginBefore *time.Time
	Search          *string
	OrderBy         UserSortField
	OrderDirection  SortDirection
}

// AdminListUsersResult contains users and the matching total.
type AdminListUsersResult struct {
	Users  []domain.User `json:"users"`
	Limit  int           `json:"limit,omitempty"`
	Offset int           `json:"offset,omitempty"`
}

// AdminStats is a snapshot of platform-wide counts for an admin dashboard.
type AdminStats struct {
	TotalUsers            int `json:"totalUsers"`
	VerifiedUsers         int `json:"verifiedUsers"`
	BannedUsers           int `json:"bannedUsers"`
	TwoFactorEnabledUsers int `json:"twoFactorEnabledUsers"`
	NeverLoggedInUsers    int `json:"neverLoggedInUsers"`
	ActiveSessions        int `json:"activeSessions"`
}

// AdminUserDetail contains a user and related administrator data.
type AdminUserDetail struct {
	User               domain.User `json:"user"`
	ActiveSessionCount int         `json:"activeSessionCount"`
	// HasPassword is whether the account can sign in with a password at all —
	// false for an OAuth-only account that never set one. The hash itself is
	// never exposed (domain.User.PasswordHash is json:"-").
	HasPassword bool                     `json:"hasPassword"`
	Providers   []domain.ProviderAccount `json:"providers"`
}

// BanUserInput identifies the user to ban.
type BanUserInput struct {
	UserID         string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// BulkActionFailure reports why one user in a bulk request didn't succeed —
// Code is the same stable AuthError code a single-user call would return
// (e.g. "last_admin", "already_banned"), safe to match on.
type BulkActionFailure struct {
	UserID  string `json:"userId"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// BulkUserActionInput is the shared input shape for every Bulk*Users method.
type BulkUserActionInput struct {
	UserIDs        []string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// BulkUserActionResult reports per-user outcome, not overall success — a
// bulk request is not transactional. Some users can succeed while others
// fail (already banned, last admin, not found); the caller must read both
// slices rather than treating a nil error as "all succeeded."
type BulkUserActionResult struct {
	Succeeded []string            `json:"succeeded"`
	Failed    []BulkActionFailure `json:"failed"`
}

// CreateUserInput contains values used to create a user.
type CreateUserInput struct {
	AppRoleID            string
	ExpectedRoleRevision uint64
	ActorID              string // the admin performing this call
	ActorSessionID       string `json:"-"`
	Email                string
	Password             string
	Name                 string
	Role                 string
}

// DeleteUserInput identifies the user to delete.
type DeleteUserInput struct {
	UserID         string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// GetUserDetailInput identifies the user to return.
type GetUserDetailInput struct {
	UserID         string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// LoginActivityInput scopes a login-activity heatmap query. UserID nil means
// a global heatmap (every user's successful logins); set, it's one user's.
type LoginActivityInput struct {
	ActorID        string
	ActorSessionID string `json:"-"`
	UserID         *string
	From           time.Time
	To             time.Time
}

// RevokeUserSessionInput identifies one user session to revoke.
type RevokeUserSessionInput struct {
	UserID         string
	SessionID      string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// RevokeUserSessionsInput identifies the user whose sessions to revoke.
type RevokeUserSessionsInput struct {
	UserID         string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// StatsRangeInput scopes a day-bucketed analytics query to [From, To].
type StatsRangeInput struct {
	ActorID        string
	ActorSessionID string `json:"-"`
	From           time.Time
	To             time.Time
}

// UnbanUserInput identifies the user to unban.
type UnbanUserInput struct {
	UserID         string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// UpdateUserRoleInput identifies a user and their new role.
type UpdateUserRoleInput struct {
	AppRoleID                  string
	ExpectedRoleRevision       uint64
	ExpectedAssignmentRevision uint64
	UserID                     string
	Role                       string
	ActorID                    string
	ActorSessionID             string `json:"-"`
}
