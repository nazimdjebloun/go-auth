package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// CreatePermission creates only business definitions; creation grants nobody.
func (s *AppPermissionsService) CreatePermission(ctx context.Context, input api.CreateAppPermissionInput) (*domain.AppPermission, error) {
	if err := validateAppKey(input.Key); err != nil {
		return nil, err
	}
	if strings.HasPrefix(input.Key, "goauth.app.") {
		return nil, domain.ErrProtectedAppPermission
	}
	if err := validateAppMetadata(input.Name, input.Description); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	p := &domain.AppPermission{ID: uuid.NewString(), Key: input.Key, Name: input.Name, Description: input.Description, IsEnabled: true, Revision: 1, CreatedAt: now, UpdatedAt: now}
	err := s.withMutation(ctx, input.Actor, "goauth.app.permissions.create", func(ctx context.Context) error {
		if err := s.definitions.InsertAppPermission(ctx, p); err != nil {
			if errors.Is(err, port.ErrDuplicateKey) {
				return domain.ErrAppPermissionExists
			}
			return err
		}
		return s.record(ctx, input.Actor, audit.EventAppPermissionCreated, map[string]any{"permissionId": p.ID, "key": p.Key})
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// UpdatePermission protects keys/library ownership and uses an expected revision.
func (s *AppPermissionsService) UpdatePermission(ctx context.Context, input api.UpdateAppPermissionInput) (*domain.AppPermission, error) {
	if err := validateAppID(input.PermissionID); err != nil {
		return nil, err
	}
	var result *domain.AppPermission
	err := s.withMutation(ctx, input.Actor, "goauth.app.permissions.update", func(ctx context.Context) error {
		p, err := s.permissions.PermissionByID(ctx, input.PermissionID)
		if err != nil {
			return err
		}
		if p == nil {
			return domain.ErrAppPermissionNotFound
		}
		if p.IsSystem {
			return domain.ErrProtectedAppPermission
		}
		if err := s.delegation(ctx, input.Actor, "", []string{p.Key}); err != nil {
			return err
		}
		if p.Revision != input.ExpectedRevision {
			return domain.ErrAppAuthorizationConflict
		}
		if input.Name != nil {
			p.Name = *input.Name
		}
		if input.Description != nil {
			p.Description = *input.Description
		}
		if input.IsEnabled != nil {
			p.IsEnabled = *input.IsEnabled
		}
		if err := validateAppMetadata(p.Name, p.Description); err != nil {
			return err
		}
		p.UpdatedAt = time.Now().UTC()
		changed, err := s.definitions.UpdateAppPermission(ctx, p, input.ExpectedRevision)
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrAppAuthorizationConflict
		}
		p.Revision++
		result = p
		return s.record(ctx, input.Actor, audit.EventAppPermissionUpdated, map[string]any{"permissionId": p.ID, "key": p.Key, "revision": p.Revision})
	})
	return result, err
}

// DeletePermission refuses system definitions and referenced business definitions.
func (s *AppPermissionsService) DeletePermission(ctx context.Context, input api.DeleteAppPermissionInput) error {
	if err := validateAppID(input.PermissionID); err != nil {
		return err
	}
	return s.withMutation(ctx, input.Actor, "goauth.app.permissions.delete", func(ctx context.Context) error {
		p, err := s.permissions.PermissionByID(ctx, input.PermissionID)
		if err != nil {
			return err
		}
		if p == nil {
			return domain.ErrAppPermissionNotFound
		}
		if p.IsSystem {
			return domain.ErrProtectedAppPermission
		}
		if p.Revision != input.ExpectedRevision {
			return domain.ErrAppAuthorizationConflict
		}
		roles, err := s.definitions.PermissionGrantRoles(ctx, p.ID)
		if err != nil {
			return err
		}
		if len(roles) > 0 {
			return domain.ErrAppPermissionInUse
		}
		if err := s.definitions.DeleteAppPermission(ctx, p.ID); err != nil {
			return err
		}
		return s.record(ctx, input.Actor, audit.EventAppPermissionDeleted, map[string]any{"permissionId": p.ID, "key": p.Key})
	})
}

// ListPermissions queries installed records for authorized role editors.
func (s *AppPermissionsService) ListPermissions(ctx context.Context, input api.ListAppPermissionsInput) ([]domain.AppPermission, error) {
	if err := s.require(ctx, input.Actor, "goauth.app.permissions.read"); err != nil {
		return nil, err
	}
	limit, err := appPage(input.Limit, input.Offset)
	if err != nil {
		return nil, err
	}
	return s.permissions.ListAppPermissions(ctx, limit, input.Offset)
}
