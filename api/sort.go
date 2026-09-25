package api

// SortDirection controls ascending or descending list order.
type SortDirection string

// SortAscending and SortDescending are the supported sort directions.
const (
	SortAscending  SortDirection = "asc"
	SortDescending SortDirection = "desc"
)

// UserSortField identifies a user-list column that may be ordered by.
type UserSortField string

// UserSortCreatedAt and UserSortUpdatedAt are supported user sort fields.
const (
	UserSortCreatedAt UserSortField = "created_at"
	UserSortUpdatedAt UserSortField = "updated_at"
)

// SessionSortField identifies a session-list column that may be ordered by.
type SessionSortField string

// SessionSortCreatedAt and the following values are supported session sort fields.
const (
	SessionSortCreatedAt    SessionSortField = "created_at"
	SessionSortExpiresAt    SessionSortField = "expires_at"
	SessionSortLastActiveAt SessionSortField = "last_active_at"
)

// InviteSortField identifies a platform-invite-list column that may be ordered by.
type InviteSortField string

// InviteSortCreatedAt and the following values are supported invite sort fields.
const (
	InviteSortCreatedAt InviteSortField = "created_at"
	InviteSortExpiresAt InviteSortField = "expires_at"
	InviteSortEmail     InviteSortField = "email"
	InviteSortStatus    InviteSortField = "status"
)

// OrgMemberSortField identifies an organization-member-list column that may be ordered by.
type OrgMemberSortField string

// OrgMemberSortJoinedAt and the following values are supported member sort fields.
const (
	OrgMemberSortJoinedAt OrgMemberSortField = "joined_at"
	OrgMemberSortRole     OrgMemberSortField = "role"
	OrgMemberSortName     OrgMemberSortField = "name"
	OrgMemberSortEmail    OrgMemberSortField = "email"
)

// UserOrgSortField identifies a user's organization-list column that may be ordered by.
type UserOrgSortField string

// UserOrgSortName and the following values are supported user-organization sort fields.
const (
	UserOrgSortName        UserOrgSortField = "name"
	UserOrgSortCreatedAt   UserOrgSortField = "created_at"
	UserOrgSortMemberCount UserOrgSortField = "member_count"
)

// OrgSortField identifies a platform organization-list column that may be ordered by.
type OrgSortField string

// OrgSortName and the following values are supported organization sort fields.
const (
	OrgSortName        OrgSortField = "name"
	OrgSortCreatedAt   OrgSortField = "created_at"
	OrgSortMemberCount OrgSortField = "member_count"
)

// OrgInviteSortField identifies an organization-invite-list column that may be ordered by.
type OrgInviteSortField string

// OrgInviteSortCreatedAt and the following values are supported organization-invite sort fields.
const (
	OrgInviteSortCreatedAt OrgInviteSortField = "created_at"
	OrgInviteSortExpiresAt OrgInviteSortField = "expires_at"
	OrgInviteSortEmail     OrgInviteSortField = "email"
	OrgInviteSortRole      OrgInviteSortField = "role"
)
