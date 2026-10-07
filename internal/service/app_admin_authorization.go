package service

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

func appActor(userID, sessionID string) api.AppPermissionActor {
	return api.AppPermissionActor{UserID: userID, SessionID: sessionID}
}

func (s *AdminService) requireOperation(ctx context.Context, userID, sessionID, key string) error {
	if s.config.AppPermissions != nil {
		return s.config.AppPermissions.require(ctx, appActor(userID, sessionID), key)
	}
	return s.requireAdmin(ctx, userID)
}

func (s *InviteService) requireOperation(ctx context.Context, userID, sessionID, key string) error {
	if s.config.AppPermissions != nil {
		return s.config.AppPermissions.require(ctx, appActor(userID, sessionID), key)
	}
	return requireAdminRole(ctx, s.users, userID)
}

func (s *OrgService) requirePlatformAdmin(ctx context.Context, userID, sessionID string) error {
	if s.appPermissions != nil {
		return s.appPermissions.RequireProtectedAdmin(ctx, appActor(userID, sessionID))
	}
	return requireAdminRole(ctx, s.users, userID)
}

func runAppMutation[T any](ctx context.Context, s *AppPermissionsService, actor api.AppPermissionActor, key string, fn func(context.Context) (T, error)) (T, error) {
	var result T
	err := s.withMutation(ctx, actor, key, func(ctx context.Context) error {
		var err error
		result, err = fn(ctx)
		return err
	})
	return result, err
}

func runProtectedAppMutation(ctx context.Context, s *AppPermissionsService, actor api.AppPermissionActor, fn func(context.Context) error) error {
	return s.users.WithAdminGuard(ctx, func(ctx context.Context) error {
		ctx = context.WithValue(ctx, appManagementContextKey{}, true)
		if err := s.RequireProtectedAdmin(ctx, actor); err != nil {
			return err
		}
		return fn(ctx)
	})
}

func runAppMutationVoid(ctx context.Context, s *AppPermissionsService, actor api.AppPermissionActor, key string, fn func(context.Context) error) error {
	return s.withMutation(ctx, actor, key, fn)
}

// RequireProtectedAdmin is a current identity and assurance guard, never delegable.
func (s *AppPermissionsService) RequireProtectedAdmin(ctx context.Context, actor api.AppPermissionActor) error {
	return s.requireProtectedAdmin(ctx, actor, true)
}

func appProtectedIdentity(ctx context.Context, s *AppPermissionsService, user *domain.User) (bool, error) {
	if user == nil {
		return false, nil
	}
	if s == nil {
		return user.Role == domain.RoleAdmin, nil
	}
	return s.IsProtectedAdmin(ctx, user.ID)
}

func appAdministrativeIdentity(ctx context.Context, s *AppPermissionsService, user *domain.User) (bool, error) {
	if user == nil {
		return false, nil
	}
	if s == nil {
		return user.Role == domain.RoleAdmin, nil
	}
	return s.HasAdministrativeAccess(ctx, user.ID)
}

func signupRequiresTwoFactor(ctx context.Context, cfg Config, user *domain.User) (bool, error) {
	if cfg.RequireEmail2FA {
		return true, nil
	}
	if cfg.AppPermissions == nil || cfg.DisableAdminTwoFactor {
		return false, nil
	}
	return cfg.AppPermissions.HasAdministrativeAccess(ctx, user.ID)
}
