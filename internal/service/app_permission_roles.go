package service

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func (s *AppPermissionsService) customRole(ctx context.Context, id string, expected uint64) (*domain.AppRole, error) {
	if err := validateAppID(id); err != nil {
		return nil, err
	}
	role, err := s.roles.RoleByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, domain.ErrAppRoleNotFound
	}
	if role.SystemKey != nil {
		return nil, domain.ErrProtectedAppRole
	}
	if role.Revision != expected {
		return nil, domain.ErrAppAuthorizationConflict
	}
	return role, nil
}

func (s *AppPermissionsService) delegation(ctx context.Context, actor api.AppPermissionActor, roleID string, keys []string) error {
	_, role, err := s.current(ctx, actor.UserID)
	if err != nil {
		return err
	}
	if role.IsAdmin() {
		return nil
	}
	if role.ID == roleID {
		return domain.ErrForbidden
	}
	held, err := s.permissions.RolePermissionKeys(ctx, role.ID)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if !slices.Contains(held, key) {
			return domain.ErrForbidden
		}
	}
	return nil
}

func (s *AppPermissionsService) grantIDs(ctx context.Context, keys []string) ([]string, error) {
	if len(keys) > 256 {
		return nil, appInvalid("Maximum 256 permission keys per role")
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		if err := validateAppKey(key); err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, appInvalid("Duplicate permission keys")
		}
		seen[key] = true
		p, err := s.permissions.PermissionByKey(ctx, key)
		if err != nil {
			return nil, err
		}
		if p == nil || !p.IsEnabled {
			return nil, domain.ErrAppPermissionNotFound
		}
		if p.IsSystem {
			if _, known := appLibraryDefinition(p.Key); !known {
				return nil, domain.ErrUnknownLibraryPermission
			}
		}
		ids = append(ids, p.ID)
	}
	return ids, nil
}

// CreateRole creates a custom identity with explicit, installed grants only.
func (s *AppPermissionsService) CreateRole(ctx context.Context, input api.CreateAppRoleInput) (*domain.AppRole, error) {
	if !appSlugPattern.MatchString(input.Slug) || input.Slug == "admin" || input.Slug == "user" {
		return nil, appInvalid("Invalid or reserved role slug")
	}
	if err := validateAppMetadata(input.Name, input.Description); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	role := &domain.AppRole{ID: uuid.NewString(), Slug: input.Slug, Name: input.Name, Description: input.Description, IsEnabled: true, Revision: 1, CreatedAt: now, UpdatedAt: now, PermissionKeys: slices.Clone(input.PermissionKeys)}
	if role.PermissionKeys == nil {
		role.PermissionKeys = []string{}
	}
	slices.Sort(role.PermissionKeys)
	err := s.withMutation(ctx, input.Actor, "goauth.app.roles.create", func(ctx context.Context) error {
		ids, err := s.grantIDs(ctx, input.PermissionKeys)
		if err != nil {
			return err
		}
		if err := s.delegation(ctx, input.Actor, "", input.PermissionKeys); err != nil {
			return err
		}
		if err := s.roles.InsertAppRole(ctx, role); err != nil {
			if errors.Is(err, port.ErrDuplicateKey) {
				return domain.ErrAppRoleExists
			}
			return err
		}
		if err := s.roles.ReplaceRoleGrants(ctx, role.ID, ids, input.Actor.UserID, now); err != nil {
			return err
		}
		return s.record(ctx, input.Actor, audit.EventAppRoleCreated, map[string]any{"roleId": role.ID, "permissionKeys": role.PermissionKeys})
	})
	if err != nil {
		return nil, err
	}
	return role, nil
}

// UpdateRole modifies custom metadata/state, never built-in roles or slugs.
func (s *AppPermissionsService) UpdateRole(ctx context.Context, input api.UpdateAppRoleInput) (*domain.AppRole, error) {
	var result *domain.AppRole
	err := s.withMutation(ctx, input.Actor, "goauth.app.roles.update", func(ctx context.Context) error {
		role, err := s.customRole(ctx, input.RoleID, input.ExpectedRevision)
		if err != nil {
			return err
		}
		keys, err := s.permissions.RoleGrantKeys(ctx, role.ID)
		if err != nil {
			return err
		}
		if err := s.delegation(ctx, input.Actor, role.ID, keys); err != nil {
			return err
		}
		if input.Name != nil {
			role.Name = *input.Name
		}
		if input.Description != nil {
			role.Description = *input.Description
		}
		if input.IsEnabled != nil {
			role.IsEnabled = *input.IsEnabled
		}
		if !role.IsEnabled && role.Slug == s.config.DefaultRoleSlug {
			return domain.ErrAppRoleInUse
		}
		if err := validateAppMetadata(role.Name, role.Description); err != nil {
			return err
		}
		role.UpdatedAt = time.Now().UTC()
		changed, err := s.roles.UpdateAppRole(ctx, role, input.ExpectedRevision)
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrAppAuthorizationConflict
		}
		role.Revision++
		role.PermissionKeys = keys
		result = role
		return s.record(ctx, input.Actor, audit.EventAppRoleUpdated, map[string]any{"roleId": role.ID, "revision": role.Revision, "isEnabled": role.IsEnabled})
	})
	return result, err
}

// SetRolePermissions replaces one custom grant set with optimistic concurrency.
func (s *AppPermissionsService) SetRolePermissions(ctx context.Context, input api.SetAppRolePermissionsInput) (*domain.AppRole, error) {
	var result *domain.AppRole
	err := s.withMutation(ctx, input.Actor, "goauth.app.roles.update", func(ctx context.Context) error {
		role, err := s.customRole(ctx, input.RoleID, input.ExpectedRevision)
		if err != nil {
			return err
		}
		old, err := s.permissions.RoleGrantKeys(ctx, role.ID)
		if err != nil {
			return err
		}
		if err := s.delegation(ctx, input.Actor, role.ID, append(slices.Clone(old), input.PermissionKeys...)); err != nil {
			return err
		}
		ids, err := s.grantIDs(ctx, input.PermissionKeys)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if err := s.roles.ReplaceRoleGrants(ctx, role.ID, ids, input.Actor.UserID, now); err != nil {
			return err
		}
		if err := s.roles.BumpRoleRevision(ctx, role.ID, now); err != nil {
			return err
		}
		role.Revision++
		role.UpdatedAt = now
		role.PermissionKeys = slices.Clone(input.PermissionKeys)
		if role.PermissionKeys == nil {
			role.PermissionKeys = []string{}
		}
		slices.Sort(role.PermissionKeys)
		result = role
		return s.record(ctx, input.Actor, audit.EventAppRoleGrantsChanged, map[string]any{"roleId": role.ID, "before": old, "after": role.PermissionKeys})
	})
	return result, err
}

// DeleteRole rejects protected/default/assigned roles and overbroad delegation.
func (s *AppPermissionsService) DeleteRole(ctx context.Context, input api.DeleteAppRoleInput) error {
	return s.withMutation(ctx, input.Actor, "goauth.app.roles.delete", func(ctx context.Context) error {
		role, err := s.customRole(ctx, input.RoleID, input.ExpectedRevision)
		if err != nil {
			return err
		}
		keys, err := s.permissions.RoleGrantKeys(ctx, role.ID)
		if err != nil {
			return err
		}
		if err := s.delegation(ctx, input.Actor, role.ID, keys); err != nil {
			return err
		}
		if role.Slug == s.config.DefaultRoleSlug {
			return domain.ErrAppRoleInUse
		}
		n, err := s.roles.RoleUserCount(ctx, role.ID)
		if err != nil {
			return err
		}
		if n > 0 {
			return domain.ErrAppRoleInUse
		}
		if err := s.roles.DeleteAppRole(ctx, role.ID); err != nil {
			return err
		}
		return s.record(ctx, input.Actor, audit.EventAppRoleDeleted, map[string]any{"roleId": role.ID})
	})
}

// ListRoles lists explicit grants; built-in admin's full access is separate policy.
func (s *AppPermissionsService) ListRoles(ctx context.Context, input api.ListAppRolesInput) ([]domain.AppRole, error) {
	if err := s.require(ctx, input.Actor, "goauth.app.roles.read"); err != nil {
		return nil, err
	}
	limit, err := appPage(input.Limit, input.Offset)
	if err != nil {
		return nil, err
	}
	roles, err := s.roles.ListAppRoles(ctx, limit, input.Offset)
	if err != nil {
		return nil, err
	}
	for i := range roles {
		roles[i].PermissionKeys, err = s.permissions.RoleGrantKeys(ctx, roles[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return roles, nil
}

// SetUserRole replaces one assignment. Protected-admin transitions require the
// actual protected actor and preserve the last usable admin in the same guard.
func (s *AppPermissionsService) SetUserRole(ctx context.Context, input api.SetAppUserRoleInput) (*api.AppUserRoleResult, error) {
	if err := validateAppID(input.UserID); err != nil {
		return nil, err
	}
	if err := validateAppID(input.RoleID); err != nil {
		return nil, err
	}
	var result *api.AppUserRoleResult
	err := s.withMutation(ctx, input.Actor, "goauth.app.roles.assign", func(ctx context.Context) error {
		target, err := s.users.GetByIDForUpdate(ctx, input.UserID)
		if err != nil {
			return err
		}
		if target == nil {
			return domain.ErrUserNotFound
		}
		if target.AppRoleAssignmentRevision != input.ExpectedAssignmentRevision {
			return domain.ErrAppAuthorizationConflict
		}
		role, err := s.roles.RoleByID(ctx, input.RoleID)
		if err != nil {
			return err
		}
		if role == nil || !role.IsEnabled {
			return domain.ErrAppRoleNotFound
		}
		if role.Revision != input.ExpectedRoleRevision {
			return domain.ErrAppAuthorizationConflict
		}
		_, actorRole, err := s.current(ctx, input.Actor.UserID)
		if err != nil {
			return err
		}
		if !actorRole.IsAdmin() && target.ID == input.Actor.UserID {
			return domain.ErrForbidden
		}
		var old *domain.AppRole
		oldKeys := []string{}
		if target.AppRoleID != nil {
			old, err = s.roles.RoleByID(ctx, *target.AppRoleID)
			if err != nil {
				return err
			}
			if old == nil {
				return domain.ErrAppRoleNotFound
			}
			oldKeys, err = s.permissions.RoleGrantKeys(ctx, old.ID)
			if err != nil {
				return err
			}
		}
		keys, err := s.permissions.RoleGrantKeys(ctx, role.ID)
		if err != nil {
			return err
		}
		if (role.IsAdmin() || (old != nil && old.IsAdmin())) && !actorRole.IsAdmin() {
			return domain.ErrForbidden
		}
		if err := s.delegation(ctx, input.Actor, "", append(slices.Clone(oldKeys), keys...)); err != nil {
			return err
		}
		if old != nil && old.IsAdmin() && !role.IsAdmin() && !target.IsBanned {
			n, err := s.roles.UsableAppAdminCount(ctx)
			if err != nil {
				return err
			}
			if n <= 1 {
				return domain.ErrCannotDeleteLastAdmin
			}
		}
		role.PermissionKeys = keys
		revision := target.AppRoleAssignmentRevision
		if target.AppRoleID == nil || *target.AppRoleID != role.ID {
			changed, err := s.roles.SetUserAppRole(ctx, target.ID, role.ID, revision, time.Now().UTC())
			if err != nil {
				return err
			}
			if !changed {
				return domain.ErrAppAuthorizationConflict
			}
			revision++
			if err := s.record(ctx, input.Actor, audit.EventAppUserRoleChanged, map[string]any{"userId": target.ID, "oldRoleId": target.AppRoleID, "roleId": role.ID, "assignmentRevision": revision}); err != nil {
				return err
			}
		}
		result = &api.AppUserRoleResult{Role: *role, AssignmentRevision: revision}
		return nil
	})
	return result, err
}

// GetUserRole authorizes target inspection independently of account existence.
func (s *AppPermissionsService) GetUserRole(ctx context.Context, input api.GetAppUserRoleInput) (*api.AppUserRoleResult, error) {
	if err := validateAppID(input.UserID); err != nil {
		return nil, err
	}
	if err := s.require(ctx, input.Actor, "goauth.app.roles.read"); err != nil {
		return nil, err
	}
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, domain.ErrUserNotFound
	}
	if user.AppRoleID == nil {
		return nil, domain.ErrAppRoleNotFound
	}
	role, err := s.roles.RoleByID(ctx, *user.AppRoleID)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, domain.ErrAppRoleNotFound
	}
	role.PermissionKeys, err = s.permissions.RoleGrantKeys(ctx, role.ID)
	return &api.AppUserRoleResult{Role: *role, AssignmentRevision: user.AppRoleAssignmentRevision}, err
}
