package port

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// AppPermissionReader reads definitions and explicit grants from current SQL state.
type AppPermissionReader interface {
	PermissionByKey(context.Context, string) (*domain.AppPermission, error)
	PermissionByID(context.Context, string) (*domain.AppPermission, error)
	ListAppPermissions(context.Context, int, int) ([]domain.AppPermission, error)
	RolePermissionKeys(context.Context, string) ([]string, error)
}

// AppPermissionWriter changes installed definitions; services own authorization.
type AppPermissionWriter interface {
	InsertAppPermission(context.Context, *domain.AppPermission) error
	UpdateAppPermission(context.Context, *domain.AppPermission, uint64) (bool, error)
	DeleteAppPermission(context.Context, string) error
	PermissionGrantRoles(context.Context, string) ([]string, error)
	RemovePermissionGrants(context.Context, string) error
}

// AppRoleStore persists roles and grants with optimistic revisions.
type AppRoleStore interface {
	RoleByID(context.Context, string) (*domain.AppRole, error)
	RoleBySlug(context.Context, string) (*domain.AppRole, error)
	ListAppRoles(context.Context, int, int) ([]domain.AppRole, error)
	InsertAppRole(context.Context, *domain.AppRole) error
	UpdateAppRole(context.Context, *domain.AppRole, uint64) (bool, error)
	DeleteAppRole(context.Context, string) error
	RoleUserCount(context.Context, string) (int, error)
	ReplaceRoleGrants(context.Context, string, []string, string, time.Time) error
	BumpRoleRevision(context.Context, string, time.Time) error
	SetUserAppRole(context.Context, string, string, uint64, time.Time) (bool, error)
}

// AppAuthorizationState serializes management transactions across processes.
type AppAuthorizationState interface {
	AppStateRevision(context.Context) (uint64, error)
	LockAppState(context.Context) error
	InitializeAppState(context.Context, time.Time) error
	BumpAppState(context.Context) error
}
