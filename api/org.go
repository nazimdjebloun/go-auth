package api

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// DeleteOrgInviteInput identifies an organization invitation and its trusted actor.
type DeleteOrgInviteInput struct {
	OrgID    string `json:"orgId"`
	InviteID string `json:"inviteId"`
	ActorID  string `json:"-"`
}

// ResendOrgInviteEmailInput identifies an organization invitation and its trusted actor.
type ResendOrgInviteEmailInput struct {
	OrgID    string `json:"orgId"`
	InviteID string `json:"inviteId"`
	ActorID  string `json:"-"`
}

// AcceptInviteInput contains values used to accept an organization invitation.
type AcceptInviteInput struct {
	UserID  string
	RawCode string
}

// AddMemberInput identifies the user and role to add to an organization.
type AddMemberInput struct {
	OrgID   string
	UserID  string
	Role    domain.OrgRole
	ActorID string
}

// AdminAddMemberInput identifies the member and role an administrator adds.
type AdminAddMemberInput struct {
	OrgID          string
	UserID         string
	Role           domain.OrgRole
	ActorID        string
	ActorSessionID string `json:"-"`
}

// AdminGetOrgInput identifies an organization to return to an administrator.
type AdminGetOrgInput struct {
	OrgID          string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// AdminListOrgMembersInput contains administrator member filters.
type AdminListOrgMembersInput struct {
	OrgID          string
	ActorID        string
	ActorSessionID string `json:"-"`
	Role           *domain.OrgRole
	Search         *string
	OrderBy        OrgMemberSortField
	OrderDirection SortDirection
	Offset         int
	Limit          *int // nil = default 20; explicit 0 = unlimited; else capped at 100
}

// AdminListOrgsInput contains administrator organization filters.
type AdminListOrgsInput struct {
	ActorID        string
	ActorSessionID string `json:"-"`
	Search         *string
	CreatedAfter   *time.Time
	CreatedBefore  *time.Time
	OrderBy        OrgSortField
	OrderDirection SortDirection
	Offset         int
	Limit          *int // nil = default 20; explicit 0 = unlimited; else capped at 100
}

// AdminListOrgsResult contains organizations and the matching total.
type AdminListOrgsResult struct {
	Orgs   []domain.Organization `json:"orgs"`
	Limit  int                   `json:"limit"`
	Offset int                   `json:"offset"`
}

// AdminListUserOrgsInput contains filters for a user's organizations.
type AdminListUserOrgsInput struct {
	ActorID        string
	ActorSessionID string `json:"-"`
	UserID         string
	Search         *string
	Role           *domain.OrgRole
	OrderBy        UserOrgSortField
	OrderDirection SortDirection
	Offset         int
	Limit          *int
}

// AdminOrgActionInput identifies an organization and administrator.
type AdminOrgActionInput struct {
	OrgID          string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// AdminRemoveMemberInput identifies the member an administrator removes.
type AdminRemoveMemberInput struct {
	OrgID          string
	UserID         string
	ActorID        string
	ActorSessionID string `json:"-"`
}

// AdminUpdateMemberRoleInput identifies the role change an administrator makes.
type AdminUpdateMemberRoleInput struct {
	OrgID          string
	UserID         string
	NewRole        domain.OrgRole
	ActorID        string
	ActorSessionID string `json:"-"`
}

// ClearActiveOrgInput identifies the session whose active organization to clear.
type ClearActiveOrgInput struct {
	SessionID string
}

// CreateOrgInput contains values used to create an organization.
type CreateOrgInput struct {
	Name    string
	Slug    string
	OwnerID string
}

// CreateOrgInviteInput contains values used to invite an organization member.
type CreateOrgInviteInput struct {
	OrgID     string
	Email     string
	Role      domain.OrgRole
	InvitedBy string
}

// DeleteOrgInput identifies an organization to delete.
type DeleteOrgInput struct {
	OrgID   string
	ActorID string
}

// GetOrgBySlugInput identifies an organization by slug and requesting user.
type GetOrgBySlugInput struct {
	Slug    string
	ActorID string
}

// GetOrgInput identifies an organization and requesting user.
type GetOrgInput struct {
	OrgID   string
	ActorID string
}

// GetOrgMembershipInput identifies a user's organization membership.
type GetOrgMembershipInput struct {
	OrgID  string
	UserID string
}

// LeaveOrgInput identifies the organization a user is leaving.
type LeaveOrgInput struct {
	OrgID  string
	UserID string
}

// ListMembersInput contains filters for an organization's members.
type ListMembersInput struct {
	OrgID          string
	ActorID        string
	Role           *domain.OrgRole
	Search         *string
	OrderBy        OrgMemberSortField
	OrderDirection SortDirection
	Offset         int
	Limit          *int // nil = default 20; explicit 0 = unlimited; else capped at 100
}

// ListMembersResult contains members and the matching total.
type ListMembersResult struct {
	Members []domain.OrgMemberDetail `json:"members"`
	Limit   int                      `json:"limit"`
	Offset  int                      `json:"offset"`
}

// ListOrgInvitesInput contains filters for an organization's invitations.
type ListOrgInvitesInput struct {
	OrgID          string
	ActorID        string
	Role           *domain.OrgRole
	Status         *string
	Search         *string
	OrderBy        OrgInviteSortField
	OrderDirection SortDirection
	Offset         int
	Limit          *int // nil = default 20; explicit 0 = unlimited; else capped at 100
}

// ListOrgInvitesResult contains invitations and the matching total.
type ListOrgInvitesResult struct {
	Invites []domain.OrgInvite `json:"invites"`
	Limit   int                `json:"limit"`
	Offset  int                `json:"offset"`
}

// ListUserOrgsInput contains filters for a user's organizations.
type ListUserOrgsInput struct {
	UserID         string
	Search         *string
	Role           *domain.OrgRole
	OrderBy        UserOrgSortField
	OrderDirection SortDirection
	Offset         int
	Limit          *int // nil = default 20; explicit 0 = unlimited; else capped at 100
}

// ListUserOrgsResult contains organizations and the matching total.
type ListUserOrgsResult struct {
	Orgs   []domain.Organization `json:"orgs"`
	Limit  int                   `json:"limit"`
	Offset int                   `json:"offset"`
}

// RemoveMemberInput identifies the member to remove from an organization.
type RemoveMemberInput struct {
	OrgID   string
	UserID  string
	ActorID string
}

// SetActiveOrgInput identifies the session and organization to activate.
type SetActiveOrgInput struct {
	SessionID string
	UserID    string
	OrgID     string
}

// UpdateMemberRoleInput identifies an organization member and their new role.
type UpdateMemberRoleInput struct {
	OrgID   string
	UserID  string
	NewRole domain.OrgRole
	ActorID string // user performing the action
}

// UpdateOrgInput contains organization changes and the requesting user.
type UpdateOrgInput struct {
	OrgID   string
	Name    *string
	Slug    *string
	ActorID string
}
