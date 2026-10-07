package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// Initialize creates protected roles/state without installing library permissions.
// It is trusted setup, never an HTTP operation or a normal role assignment path.
func (s *AppPermissionsService) Initialize(ctx context.Context, input api.InitializeAppPermissionsInput) error {
	return s.users.WithAdminGuard(ctx, func(ctx context.Context) error {
		revision, err := s.state.AppStateRevision(ctx)
		if err != nil {
			return err
		}
		if revision > 0 {
			return domain.ErrAppPermissionsInitialized
		}
		user, err := s.users.GetByIDForUpdate(ctx, input.AdministratorUserID)
		if err != nil {
			return err
		}
		if user == nil || user.IsBanned || user.AppRoleID != nil {
			return appInvalid("Initial administrator must be an existing eligible setup account without an app role")
		}
		now := time.Now().UTC()
		if err := s.state.InitializeAppState(ctx, now); err != nil {
			if errors.Is(err, port.ErrDuplicateKey) {
				return domain.ErrAppPermissionsInitialized
			}
			return err
		}
		var adminID string
		for _, identity := range []string{domain.AppRoleAdmin, domain.AppRoleUser} {
			slug, name := "user", "User"
			if identity == domain.AppRoleAdmin {
				slug, name = "admin", "Admin"
			}
			role := &domain.AppRole{ID: uuid.NewString(), Slug: slug, Name: name, IsEnabled: true, SystemKey: &identity, Revision: 1, CreatedAt: now, UpdatedAt: now}
			if err := s.roles.InsertAppRole(ctx, role); err != nil {
				return err
			}
			if identity == domain.AppRoleAdmin {
				adminID = role.ID
			}
		}
		changed, err := s.roles.SetUserAppRole(ctx, user.ID, adminID, user.AppRoleAssignmentRevision, now)
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrAppAuthorizationConflict
		}
		return s.record(ctx, api.AppPermissionActor{UserID: user.ID}, audit.EventAppAuthorizationInitialized, map[string]any{"adminRoleId": adminID})
	})
}

// AssignBaseline follows insertion of an unassigned user in the same transaction.
// Insert-before-role-lock avoids inversion with management's all-user guard.
func (s *AppPermissionsService) AssignBaseline(ctx context.Context, user *domain.User) error {
	role, err := s.baselineRole(ctx)
	if err != nil {
		return err
	}
	changed, err := s.roles.SetUserAppRole(ctx, user.ID, role.ID, 0, user.UpdatedAt)
	if err != nil {
		return err
	}
	if !changed {
		return domain.ErrAppAuthorizationConflict
	}
	user.AppRoleID, user.AppRoleAssignmentRevision = &role.ID, 1
	return nil
}

func (s *AppPermissionsService) baselineRole(ctx context.Context) (*domain.AppRole, error) {
	// Initialization is permanent; its presence needs no management lock.
	revision, err := s.state.AppStateRevision(ctx)
	if err != nil {
		return nil, err
	}
	if revision == 0 {
		return nil, domain.ErrAppPermissionsNotInitialized
	}
	role, err := s.roles.RoleBySlugForShare(ctx, s.config.DefaultRoleSlug)
	if err != nil {
		return nil, err
	}
	if role == nil || !role.IsEnabled || role.IsAdmin() {
		return nil, domain.ErrAppRoleNotFound
	}
	return role, nil
}

// AssignCreatedRole applies the same delegation limit to administrative creation
// as to assignment of an existing account. The caller owns the guarded transaction.
func (s *AppPermissionsService) AssignCreatedRole(ctx context.Context, actor api.AppPermissionActor, user *domain.User, roleID string, revision uint64) error {
	if roleID == "" {
		role, err := s.baselineRole(ctx)
		if err != nil {
			return err
		}
		user.AppRoleID, user.AppRoleAssignmentRevision = &role.ID, 1
		return nil
	}
	if err := validateAppID(roleID); err != nil {
		return err
	}
	if err := s.require(ctx, actor, "goauth.app.roles.assign"); err != nil {
		return err
	}
	role, err := s.roles.RoleByID(ctx, roleID)
	if err != nil {
		return err
	}
	if role == nil || !role.IsEnabled {
		return domain.ErrAppRoleNotFound
	}
	if role.Revision != revision {
		return domain.ErrAppAuthorizationConflict
	}
	_, actorRole, err := s.current(ctx, actor.UserID)
	if err != nil {
		return err
	}
	if role.IsAdmin() && !actorRole.IsAdmin() {
		return domain.ErrForbidden
	}
	keys, err := s.permissions.RoleGrantKeys(ctx, role.ID)
	if err != nil {
		return err
	}
	if err := s.delegation(ctx, actor, "", keys); err != nil {
		return err
	}
	user.AppRoleID, user.AppRoleAssignmentRevision = &role.ID, 1
	return nil
}
