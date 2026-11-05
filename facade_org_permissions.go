package goauth

import (
	"context"
	"net/http"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// InitializeOrgPermissions enables authorization for an existing org as its owner.
func (a *Auth) InitializeOrgPermissions(ctx context.Context, input api.InitializeOrgPermissionsInput) error {
	if a.services.OrgPermissions == nil {
		return domain.ErrOrgPermissionsDisabled
	}
	return a.services.OrgPermissions.Initialize(ctx, input)
}

// RequireOrgPermission checks live org access after RequireAuth.
func (a *Auth) RequireOrgPermission(key string) func(http.Handler) http.Handler {
	return middleware.RequireOrgPermission(a.services.OrgPermissions, key)
}

// RequireActiveOrgPermission uses the session's org ID and checks live grants.
func (a *Auth) RequireActiveOrgPermission(key string) func(http.Handler) http.Handler {
	return middleware.RequireActiveOrgPermission(a.services.OrgPermissions, key)
}

// RequireOrgPermissionScope passes the authorized tenant scope to an application handler.
// It includes authentication; prefer ProtectOrgScope for browser HTTP routes.
func (a *Auth) RequireOrgPermissionScope(key string, next OrgHandlerFunc) http.Handler {
	return a.RequireAuth(a.RequireOrgPermission(key)(a.orgScopeHandler(next)))
}

// RequireActiveOrgPermissionScope checks live grants before exposing the active scope.
// It includes authentication; prefer ProtectActiveOrgScope for browser HTTP routes.
func (a *Auth) RequireActiveOrgPermissionScope(key string, next OrgHandlerFunc) http.Handler {
	return a.RequireAuth(a.RequireActiveOrgPermission(key)(a.orgScopeHandler(next)))
}
