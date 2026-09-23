package goauth

import "github.com/nazimdjebloun/go-auth/port"

// SortDirection controls whether a list is ordered from low to high or high
// to low. Use SortAscending or SortDescending.
type SortDirection = port.SortDirection

// SortAscending and SortDescending define sort direction values.
const (
	SortAscending  = port.SortAscending
	SortDescending = port.SortDescending
)

// UserSortField identifies a supported user-list ordering.
type UserSortField = port.UserSortField

// UserSortCreatedAt and UserSortUpdatedAt define user sort fields.
const (
	UserSortCreatedAt = port.UserSortCreatedAt
	UserSortUpdatedAt = port.UserSortUpdatedAt
)

// SessionSortField identifies a supported session-list ordering.
type SessionSortField = port.SessionSortField

// SessionSortCreatedAt and the following values define session sort fields.
const (
	SessionSortCreatedAt    = port.SessionSortCreatedAt
	SessionSortExpiresAt    = port.SessionSortExpiresAt
	SessionSortLastActiveAt = port.SessionSortLastActiveAt
)

// InviteSortField identifies a supported platform-invite-list ordering.
type InviteSortField = port.InviteSortField

// InviteSortCreatedAt and the following values define invite sort fields.
const (
	InviteSortCreatedAt = port.InviteSortCreatedAt
	InviteSortExpiresAt = port.InviteSortExpiresAt
	InviteSortEmail     = port.InviteSortEmail
	InviteSortStatus    = port.InviteSortStatus
)

// OrgMemberSortField identifies a supported organization-member-list ordering.
type OrgMemberSortField = port.OrgMemberSortField

// OrgMemberSortJoinedAt and the following values define member sort fields.
const (
	OrgMemberSortJoinedAt = port.OrgMemberSortJoinedAt
	OrgMemberSortRole     = port.OrgMemberSortRole
	OrgMemberSortName     = port.OrgMemberSortName
	OrgMemberSortEmail    = port.OrgMemberSortEmail
)

// UserOrgSortField identifies a supported user's organization-list ordering.
type UserOrgSortField = port.UserOrgSortField

// UserOrgSortName and the following values define user organization sort fields.
const (
	UserOrgSortName        = port.UserOrgSortName
	UserOrgSortCreatedAt   = port.UserOrgSortCreatedAt
	UserOrgSortMemberCount = port.UserOrgSortMemberCount
)

// OrgSortField identifies a supported platform organization-list ordering.
type OrgSortField = port.OrgSortField

// OrgSortName and the following values define organization sort fields.
const (
	OrgSortName        = port.OrgSortName
	OrgSortCreatedAt   = port.OrgSortCreatedAt
	OrgSortMemberCount = port.OrgSortMemberCount
)

// OrgInviteSortField identifies a supported organization-invite-list ordering.
type OrgInviteSortField = port.OrgInviteSortField

// OrgInviteSortCreatedAt and the following values define organization invite sort fields.
const (
	OrgInviteSortCreatedAt = port.OrgInviteSortCreatedAt
	OrgInviteSortExpiresAt = port.OrgInviteSortExpiresAt
	OrgInviteSortEmail     = port.OrgInviteSortEmail
	OrgInviteSortRole      = port.OrgInviteSortRole
)
