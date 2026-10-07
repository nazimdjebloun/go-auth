package api

import "github.com/nazimdjebloun/go-auth/domain"

// AppPermissionActor is supplied by trusted backend authentication, never JSON.
type AppPermissionActor struct {
	UserID    string
	SessionID string
}

// InitializeAppPermissionsInput is for trusted first-install setup only.
type InitializeAppPermissionsInput struct{ AdministratorUserID string }

// CheckAppPermissionInput checks one exact key for the current account role.
type CheckAppPermissionInput struct {
	Actor         AppPermissionActor
	PermissionKey string
}

// AppPermissionDecision separates denial from infrastructure errors.
type AppPermissionDecision struct {
	Allowed bool `json:"allowed"`
}

// CreateAppPermissionInput defines an application-owned business action.
type CreateAppPermissionInput struct {
	Actor                  AppPermissionActor
	Key, Name, Description string
}

// UpdateAppPermissionInput distinguishes unchanged fields from explicit empty values.
type UpdateAppPermissionInput struct {
	Actor             AppPermissionActor
	PermissionID      string
	ExpectedRevision  uint64
	Name, Description *string
	IsEnabled         *bool
}

// DeleteAppPermissionInput guards business-definition deletion against stale callers.
type DeleteAppPermissionInput struct {
	Actor            AppPermissionActor
	PermissionID     string
	ExpectedRevision uint64
}

// ListAppPermissionsInput paginates installed definitions, including library rows.
type ListAppPermissionsInput struct {
	Actor         AppPermissionActor
	Limit, Offset int
}

// CreateAppRoleInput assigns only explicitly installed keys to a custom role.
type CreateAppRoleInput struct {
	Actor                   AppPermissionActor
	Slug, Name, Description string
	PermissionKeys          []string
}

// UpdateAppRoleInput changes custom metadata/state without changing its slug.
type UpdateAppRoleInput struct {
	Actor             AppPermissionActor
	RoleID            string
	ExpectedRevision  uint64
	Name, Description *string
	IsEnabled         *bool
}

// SetAppRolePermissionsInput replaces the entire grant set; empty removes all grants.
type SetAppRolePermissionsInput struct {
	Actor            AppPermissionActor
	RoleID           string
	ExpectedRevision uint64
	PermissionKeys   []string
}

// DeleteAppRoleInput refuses assigned and configured-default roles.
type DeleteAppRoleInput struct {
	Actor            AppPermissionActor
	RoleID           string
	ExpectedRevision uint64
}

// ListAppRolesInput paginates roles and their explicit grant sets.
type ListAppRolesInput struct {
	Actor         AppPermissionActor
	Limit, Offset int
}

// SetAppUserRoleInput replaces one assignment and checks both observed revisions.
type SetAppUserRoleInput struct {
	Actor                                            AppPermissionActor
	UserID, RoleID                                   string
	ExpectedRoleRevision, ExpectedAssignmentRevision uint64
}

// GetAppUserRoleInput describes a target account independently of the actor.
type GetAppUserRoleInput struct {
	Actor  AppPermissionActor
	UserID string
}

// AppUserRoleResult is the current role and its account assignment revision.
type AppUserRoleResult struct {
	Role               domain.AppRole `json:"role"`
	AssignmentRevision uint64         `json:"assignmentRevision"`
}

// ListAppEffectivePermissionsInput defaults the target to the authenticated actor.
type ListAppEffectivePermissionsInput struct {
	Actor  AppPermissionActor
	UserID string
}

// AppAccess describes current effective access; client flags confer no authority.
type AppAccess struct {
	Role               domain.AppRole `json:"role"`
	IsFullAccess       bool           `json:"isFullAccess"`
	PermissionKeys     []string       `json:"permissionKeys"`
	AssignmentRevision uint64         `json:"assignmentRevision"`
	Revision           uint64         `json:"revision"`
}

// UpdateAppLibraryPermissionsInput installs/removes fixed definitions in one batch.
type UpdateAppLibraryPermissionsInput struct {
	Actor          AppPermissionActor
	Create, Delete []string
}

// UpdateAppLibraryPermissionsResult reports actual changes and harmless retry no-ops.
type UpdateAppLibraryPermissionsResult struct {
	Created   []string `json:"created"`
	Deleted   []string `json:"deleted"`
	Unchanged []string `json:"unchanged"`
}
