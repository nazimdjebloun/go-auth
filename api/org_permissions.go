package api

import "github.com/nazimdjebloun/go-auth/domain"

// OrgPermissionActor is supplied by trusted backend authentication, never JSON.
type OrgPermissionActor struct {
	OrgID     string `json:"-"`
	UserID    string `json:"-"`
	SessionID string `json:"-"`
}

// InitializeOrgPermissionsInput enables the catalog for an existing organization.
type InitializeOrgPermissionsInput struct {
	Actor OrgPermissionActor `json:"-"`
}

// CheckOrgPermissionInput checks one exact key for the current membership role.
type CheckOrgPermissionInput struct {
	Actor         OrgPermissionActor `json:"-"`
	PermissionKey string
}

// OrgPermissionDecision separates denial from infrastructure errors.
type OrgPermissionDecision struct {
	Allowed bool `json:"allowed"`
}

// CreateOrgPermissionInput defines an application-owned business action.
type CreateOrgPermissionInput struct {
	Actor                  OrgPermissionActor `json:"-"`
	Key, Name, Description string
}

// UpdateOrgPermissionInput distinguishes unchanged fields from explicit empty values.
type UpdateOrgPermissionInput struct {
	Actor             OrgPermissionActor `json:"-"`
	PermissionID      string
	ExpectedRevision  uint64
	Name, Description *string
	IsEnabled         *bool
}

// DeleteOrgPermissionInput guards business-definition deletion against stale callers.
type DeleteOrgPermissionInput struct {
	Actor            OrgPermissionActor `json:"-"`
	PermissionID     string
	ExpectedRevision uint64
}

// ListOrgPermissionsInput paginates installed definitions, including library rows.
type ListOrgPermissionsInput struct {
	Actor         OrgPermissionActor `json:"-"`
	Limit, Offset int
}

// CreateOrgRoleInput assigns only explicitly installed keys to a custom role.
type CreateOrgRoleInput struct {
	Actor                   OrgPermissionActor `json:"-"`
	Slug, Name, Description string
	PermissionKeys          []string
}

// UpdateOrgRoleInput changes custom metadata/state without changing its slug.
type UpdateOrgRoleInput struct {
	Actor             OrgPermissionActor `json:"-"`
	RoleID            string
	ExpectedRevision  uint64
	Name, Description *string
	IsEnabled         *bool
}

// SetOrgRolePermissionsInput replaces the entire grant set; empty removes all grants.
type SetOrgRolePermissionsInput struct {
	Actor            OrgPermissionActor `json:"-"`
	RoleID           string
	ExpectedRevision uint64
	PermissionKeys   []string
}

// DeleteOrgRoleInput refuses assigned roles.
type DeleteOrgRoleInput struct {
	Actor            OrgPermissionActor `json:"-"`
	RoleID           string
	ExpectedRevision uint64
}

// ListOrgRolesInput paginates roles and their explicit grant sets.
type ListOrgRolesInput struct {
	Actor         OrgPermissionActor `json:"-"`
	Limit, Offset int
}

// SetOrgMemberRoleInput replaces one assignment and checks both observed revisions.
type SetOrgMemberRoleInput struct {
	Actor                                            OrgPermissionActor `json:"-"`
	UserID, RoleID                                   string
	ExpectedRoleRevision, ExpectedAssignmentRevision uint64
}

// GetOrgMemberRoleInput describes a target member independently of the actor.
type GetOrgMemberRoleInput struct {
	Actor  OrgPermissionActor `json:"-"`
	UserID string
}

// OrgMemberRoleResult is the current role and its membership assignment revision.
type OrgMemberRoleResult struct {
	Role               domain.OrgPermissionRole `json:"role"`
	AssignmentRevision uint64                   `json:"assignmentRevision"`
}

// ListOrgEffectivePermissionsInput defaults the target to the authenticated actor.
type ListOrgEffectivePermissionsInput struct {
	Actor  OrgPermissionActor `json:"-"`
	UserID string
}

// OrgAccess describes current effective access; client flags confer no authority.
type OrgAccess struct {
	Role               domain.OrgPermissionRole `json:"role"`
	IsFullAccess       bool                     `json:"isFullAccess"`
	PermissionKeys     []string                 `json:"permissionKeys"`
	AssignmentRevision uint64                   `json:"assignmentRevision"`
	Revision           uint64                   `json:"revision"`
}

// UpdateOrgLibraryPermissionsInput installs/removes fixed definitions in one batch.
type UpdateOrgLibraryPermissionsInput struct {
	Actor          OrgPermissionActor `json:"-"`
	Create, Delete []string
}

// UpdateOrgLibraryPermissionsResult reports actual changes and harmless retry no-ops.
type UpdateOrgLibraryPermissionsResult struct {
	Created   []string `json:"created"`
	Deleted   []string `json:"deleted"`
	Unchanged []string `json:"unchanged"`
}
