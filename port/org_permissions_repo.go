package port

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// OrgPermissionReader always scopes definitions and grants to one organization.
type OrgPermissionReader interface {
	PermissionByKey(context.Context, string, string) (*domain.OrgPermission, error)
	PermissionByID(context.Context, string, string) (*domain.OrgPermission, error)
	ListOrgPermissions(context.Context, string, int, int) ([]domain.OrgPermission, error)
	RolePermissionKeys(context.Context, string, string) ([]string, error)
	RoleGrantKeys(context.Context, string, string) ([]string, error)
	EnabledBusinessPermissionKeys(context.Context, string) ([]string, error)
}

// OrgPermissionWriter joins the service's guarded transaction.
type OrgPermissionWriter interface {
	InsertOrgPermission(context.Context, *domain.OrgPermission) error
	UpdateOrgPermission(context.Context, *domain.OrgPermission, uint64) (bool, error)
	DeleteOrgPermission(context.Context, string, string) error
	PermissionGrantRoles(context.Context, string, string) ([]string, error)
	RemovePermissionGrants(context.Context, string, string) error
}

// OrgMemberRoleStore keeps explicit assignments consistent with fixed-role writes,
// including while organization permission enforcement is disabled.
type OrgMemberRoleStore interface {
	RoleBySlug(context.Context, string, string) (*domain.OrgPermissionRole, error)
	MemberRole(context.Context, string, string) (*domain.OrgPermissionRole, uint64, error)
	SetMemberRole(context.Context, string, string, string, uint64) (bool, error)
}

// OrgPermissionRoleStore persists org-local roles, membership assignments and invites.
type OrgPermissionRoleStore interface {
	OrgMemberRoleStore
	RoleByID(context.Context, string, string) (*domain.OrgPermissionRole, error)
	ListOrgRoles(context.Context, string, int, int) ([]domain.OrgPermissionRole, error)
	InsertOrgRole(context.Context, *domain.OrgPermissionRole) error
	UpdateOrgRole(context.Context, *domain.OrgPermissionRole, uint64) (bool, error)
	DeleteOrgRole(context.Context, string, string) error
	RoleUserCount(context.Context, string, string) (int, error)
	ReplaceRoleGrants(context.Context, string, string, []string, string, time.Time) error
	BumpRoleRevision(context.Context, string, string, time.Time) error
	SetInviteRole(context.Context, string, string, string, uint64) error
	InviteRole(context.Context, string, string) (*domain.OrgPermissionRole, uint64, error)
}

// OrgAuthorizationState locks the organization before reading mutable authorization.
type OrgAuthorizationState interface {
	LockOrg(context.Context, string) error
	OrgStateRevision(context.Context, string) (uint64, error)
	InitializeOrgState(context.Context, string, time.Time) error
	BumpOrgState(context.Context, string) error
}
