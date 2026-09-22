package port

// SortDirection controls ascending or descending list order.
type SortDirection string

const (
	SortAscending  SortDirection = "asc"
	SortDescending SortDirection = "desc"
)

// UserSortField identifies a user-list column that may be ordered by.
type UserSortField string

const (
	UserSortCreatedAt UserSortField = "created_at"
	UserSortUpdatedAt UserSortField = "updated_at"
)

// SessionSortField identifies a session-list column that may be ordered by.
type SessionSortField string

const (
	SessionSortCreatedAt    SessionSortField = "created_at"
	SessionSortExpiresAt    SessionSortField = "expires_at"
	SessionSortLastActiveAt SessionSortField = "last_active_at"
)

// InviteSortField identifies a platform-invite-list column that may be ordered by.
type InviteSortField string

const (
	InviteSortCreatedAt InviteSortField = "created_at"
	InviteSortExpiresAt InviteSortField = "expires_at"
	InviteSortEmail     InviteSortField = "email"
	InviteSortStatus    InviteSortField = "status"
)

// OrgMemberSortField identifies an organization-member-list column that may be ordered by.
type OrgMemberSortField string

const (
	OrgMemberSortJoinedAt OrgMemberSortField = "joined_at"
	OrgMemberSortRole     OrgMemberSortField = "role"
	OrgMemberSortName     OrgMemberSortField = "name"
	OrgMemberSortEmail    OrgMemberSortField = "email"
)

// UserOrgSortField identifies a user's organization-list column that may be ordered by.
type UserOrgSortField string

const (
	UserOrgSortName        UserOrgSortField = "name"
	UserOrgSortCreatedAt   UserOrgSortField = "created_at"
	UserOrgSortMemberCount UserOrgSortField = "member_count"
)

// OrgSortField identifies a platform organization-list column that may be ordered by.
type OrgSortField string

const (
	OrgSortName        OrgSortField = "name"
	OrgSortCreatedAt   OrgSortField = "created_at"
	OrgSortMemberCount OrgSortField = "member_count"
)

// OrgInviteSortField identifies an organization-invite-list column that may be ordered by.
type OrgInviteSortField string

const (
	OrgInviteSortCreatedAt OrgInviteSortField = "created_at"
	OrgInviteSortExpiresAt OrgInviteSortField = "expires_at"
	OrgInviteSortEmail     OrgInviteSortField = "email"
	OrgInviteSortRole      OrgInviteSortField = "role"
)
