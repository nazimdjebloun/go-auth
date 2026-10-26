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

func (s *OrgPermissionsService) customRole(ctx context.Context, orgID, id string, expected uint64) (*domain.OrgPermissionRole, error) {
	if err := validateOrgID(id); err != nil {
		return nil, err
	}
	role, err := s.roles.RoleByID(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, domain.ErrOrgRoleNotFound
	}
	if role.SystemKey != nil {
		return nil, domain.ErrProtectedOrgRole
	}
	if role.Revision != expected {
		return nil, domain.ErrOrgAuthorizationConflict
	}
	return role, nil
}

func (s *OrgPermissionsService) delegation(ctx context.Context, actor api.OrgPermissionActor, roleID string, keys []string) error {
	_, role, err := s.current(ctx, actor)
	if err != nil {
		return err
	}
	if role.IsOwner() {
		return nil
	}
	if role.ID == roleID {
		return domain.ErrOrgForbidden
	}
	held, err := s.effectiveKeys(ctx, actor.OrgID, role, false)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if !slices.Contains(held, key) {
			return domain.ErrOrgForbidden
		}
	}
	return nil
}

func (s *OrgPermissionsService) grantIDs(ctx context.Context, orgID string, keys []string) ([]string, error) {
	if len(keys) > 256 {
		return nil, orgInvalid("Maximum 256 permission keys per role")
	}
	seen := map[string]bool{}
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		if err := validateOrgKey(key); err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, orgInvalid("Duplicate permission keys")
		}
		seen[key] = true
		p, err := s.permissions.PermissionByKey(ctx, orgID, key)
		if err != nil {
			return nil, err
		}
		if p == nil || !p.IsEnabled {
			return nil, domain.ErrOrgPermissionNotFound
		}
		if p.IsSystem {
			if _, known := orgLibraryDefinition(p.Key); !known {
				return nil, domain.ErrUnknownLibraryPermission
			}
		}
		ids = append(ids, p.ID)
	}
	return ids, nil
}

// CreateRole creates a custom identity with explicit, installed grants only.
func (s *OrgPermissionsService) CreateRole(ctx context.Context, input api.CreateOrgRoleInput) (*domain.OrgPermissionRole, error) {
	if !orgSlugPattern.MatchString(input.Slug) || input.Slug == "admin" || input.Slug == "member" || input.Slug == "owner" {
		return nil, orgInvalid("Invalid or reserved role slug")
	}
	if err := validateOrgMetadata(input.Name, input.Description); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	role := &domain.OrgPermissionRole{OrgID: input.Actor.OrgID, ID: uuid.NewString(), Slug: input.Slug, Name: input.Name, Description: input.Description, IsEnabled: true, Revision: 1, CreatedAt: now, UpdatedAt: now, PermissionKeys: slices.Clone(input.PermissionKeys)}
	if role.PermissionKeys == nil {
		role.PermissionKeys = []string{}
	}
	slices.Sort(role.PermissionKeys)
	err := s.withMutation(ctx, input.Actor, "goauth.org.roles.create", func(ctx context.Context) error {
		ids, err := s.grantIDs(ctx, input.Actor.OrgID, input.PermissionKeys)
		if err != nil {
			return err
		}
		if err := s.delegation(ctx, input.Actor, "", input.PermissionKeys); err != nil {
			return err
		}
		if err := s.roles.InsertOrgRole(ctx, role); err != nil {
			if errors.Is(err, port.ErrDuplicateKey) {
				return domain.ErrOrgRoleExists
			}
			return err
		}
		if err := s.roles.ReplaceRoleGrants(ctx, input.Actor.OrgID, role.ID, ids, input.Actor.UserID, now); err != nil {
			return err
		}
		return s.record(ctx, input.Actor, audit.EventOrgRoleCreated, map[string]any{"roleId": role.ID, "permissionKeys": role.PermissionKeys})
	})
	if err != nil {
		return nil, err
	}
	return role, nil
}

// UpdateRole modifies custom metadata/state, never built-in roles or slugs.
func (s *OrgPermissionsService) UpdateRole(ctx context.Context, input api.UpdateOrgRoleInput) (*domain.OrgPermissionRole, error) {
	var result *domain.OrgPermissionRole
	err := s.withMutation(ctx, input.Actor, "goauth.org.roles.update", func(ctx context.Context) error {
		role, err := s.customRole(ctx, input.Actor.OrgID, input.RoleID, input.ExpectedRevision)
		if err != nil {
			return err
		}
		keys, err := s.permissions.RoleGrantKeys(ctx, input.Actor.OrgID, role.ID)
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
		if !role.IsEnabled && role.SystemKey != nil {
			return domain.ErrOrgRoleInUse
		}
		if err := validateOrgMetadata(role.Name, role.Description); err != nil {
			return err
		}
		role.UpdatedAt = time.Now().UTC()
		changed, err := s.roles.UpdateOrgRole(ctx, role, input.ExpectedRevision)
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrOrgAuthorizationConflict
		}
		role.Revision++
		role.PermissionKeys = keys
		result = role
		return s.record(ctx, input.Actor, audit.EventOrgRoleUpdated, map[string]any{"roleId": role.ID, "revision": role.Revision, "isEnabled": role.IsEnabled})
	})
	return result, err
}

// SetRolePermissions replaces one custom grant set with optimistic concurrency.
func (s *OrgPermissionsService) SetRolePermissions(ctx context.Context, input api.SetOrgRolePermissionsInput) (*domain.OrgPermissionRole, error) {
	var result *domain.OrgPermissionRole
	err := s.withMutation(ctx, input.Actor, "goauth.org.roles.update", func(ctx context.Context) error {
		role, err := s.customRole(ctx, input.Actor.OrgID, input.RoleID, input.ExpectedRevision)
		if err != nil {
			return err
		}
		old, err := s.permissions.RoleGrantKeys(ctx, input.Actor.OrgID, role.ID)
		if err != nil {
			return err
		}
		if err := s.delegation(ctx, input.Actor, role.ID, append(slices.Clone(old), input.PermissionKeys...)); err != nil {
			return err
		}
		ids, err := s.grantIDs(ctx, input.Actor.OrgID, input.PermissionKeys)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		if err := s.roles.ReplaceRoleGrants(ctx, input.Actor.OrgID, role.ID, ids, input.Actor.UserID, now); err != nil {
			return err
		}
		if err := s.roles.BumpRoleRevision(ctx, input.Actor.OrgID, role.ID, now); err != nil {
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
		return s.record(ctx, input.Actor, audit.EventOrgRoleGrantsChanged, map[string]any{"roleId": role.ID, "before": old, "after": role.PermissionKeys})
	})
	return result, err
}

// DeleteRole rejects protected/assigned roles and overbroad delegation.
func (s *OrgPermissionsService) DeleteRole(ctx context.Context, input api.DeleteOrgRoleInput) error {
	return s.withMutation(ctx, input.Actor, "goauth.org.roles.delete", func(ctx context.Context) error {
		role, err := s.customRole(ctx, input.Actor.OrgID, input.RoleID, input.ExpectedRevision)
		if err != nil {
			return err
		}
		keys, err := s.permissions.RoleGrantKeys(ctx, input.Actor.OrgID, role.ID)
		if err != nil {
			return err
		}
		if err := s.delegation(ctx, input.Actor, role.ID, keys); err != nil {
			return err
		}
		if role.SystemKey != nil {
			return domain.ErrOrgRoleInUse
		}
		n, err := s.roles.RoleUserCount(ctx, input.Actor.OrgID, role.ID)
		if err != nil {
			return err
		}
		if n > 0 {
			return domain.ErrOrgRoleInUse
		}
		if err := s.roles.DeleteOrgRole(ctx, input.Actor.OrgID, role.ID); err != nil {
			return err
		}
		return s.record(ctx, input.Actor, audit.EventOrgRoleDeleted, map[string]any{"roleId": role.ID})
	})
}

// ListRoles lists explicit grants; built-in admin's full access is separate policy.
func (s *OrgPermissionsService) ListRoles(ctx context.Context, input api.ListOrgRolesInput) ([]domain.OrgPermissionRole, error) {
	if err := s.require(ctx, input.Actor, "goauth.org.roles.read"); err != nil {
		return nil, err
	}
	limit, err := orgPage(input.Limit, input.Offset)
	if err != nil {
		return nil, err
	}
	roles, err := s.roles.ListOrgRoles(ctx, input.Actor.OrgID, limit, input.Offset)
	if err != nil {
		return nil, err
	}
	for i := range roles {
		roles[i].PermissionKeys, err = s.explicitKeys(ctx, input.Actor.OrgID, &roles[i])
		if err != nil {
			return nil, err
		}
	}
	return roles, nil
}
