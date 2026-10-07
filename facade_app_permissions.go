package goauth

import (
	"context"
	"net/http"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// InitializeAppPermissions is trusted first-install setup with no HTTP route.
// It creates protected roles and the initial assignment, not permission records.
func (a *Auth) InitializeAppPermissions(ctx context.Context, input api.InitializeAppPermissionsInput) error {
	if a.services.AppPermissions == nil {
		return domain.ErrAppPermissionsDisabled
	}
	return a.services.AppPermissions.Initialize(ctx, input)
}

// RequireAppPermission checks current SQL access after RequireAuth middleware.
func (a *Auth) RequireAppPermission(key string) func(http.Handler) http.Handler {
	return middleware.RequireAppPermission(a.services.AppPermissions, key)
}
