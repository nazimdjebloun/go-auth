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
func (s *OrgPermissionsService) CreatePermission(ctx context.Context, input api.CreateOrgPermissionInput) (*domain.OrgPermission, error) {
	if err := validateOrgKey(input.Key); err != nil {
		return nil, err
	}
	if strings.HasPrefix(input.Key, "goauth.org.") {
		return nil, domain.ErrProtectedOrgPermission
	}
	if err := validateOrgMetadata(input.Name, input.Description); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	p := &domain.OrgPermission{OrgID: input.Actor.OrgID, ID: uuid.NewString(), Key: input.Key, Name: input.Name, Description: input.Description, IsEnabled: true, Revision: 1, CreatedAt: now, UpdatedAt: now}
	err := s.withMutation(ctx, input.Actor, "goauth.org.permissions.create", func(ctx context.Context) error {
		if err := s.definitions.InsertOrgPermission(ctx, p); err != nil {
			if errors.Is(err, port.ErrDuplicateKey) {
				return domain.ErrOrgPermissionExists
			}
			return err
		}
		return s.record(ctx, input.Actor, audit.EventOrgPermissionCreated, map[string]any{"permissionId": p.ID, "key": p.Key})
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// UpdatePermission protects keys/library ownership and uses an expected revision.
func (s *OrgPermissionsService) UpdatePermission(ctx context.Context, input api.UpdateOrgPermissionInput) (*domain.OrgPermission, error) {
	if err := validateOrgID(input.PermissionID); err != nil {
		return nil, err
	}
	var result *domain.OrgPermission
	err := s.withMutation(ctx, input.Actor, "goauth.org.permissions.update", func(ctx context.Context) error {
		p, err := s.permissions.PermissionByID(ctx, input.Actor.OrgID, input.PermissionID)
		if err != nil {
			return err
		}
		if p == nil {
			return domain.ErrOrgPermissionNotFound
		}
		if p.IsSystem {
			return domain.ErrProtectedOrgPermission
		}
		if err := s.delegation(ctx, input.Actor, "", []string{p.Key}); err != nil {
			return err
		}
		if p.Revision != input.ExpectedRevision {
			return domain.ErrOrgAuthorizationConflict
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
		if err := validateOrgMetadata(p.Name, p.Description); err != nil {
			return err
		}
		p.UpdatedAt = time.Now().UTC()
		changed, err := s.definitions.UpdateOrgPermission(ctx, p, input.ExpectedRevision)
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrOrgAuthorizationConflict
		}
		p.Revision++
		result = p
		return s.record(ctx, input.Actor, audit.EventOrgPermissionUpdated, map[string]any{"permissionId": p.ID, "key": p.Key, "revision": p.Revision})
	})
	return result, err
}

// DeletePermission refuses system definitions and referenced business definitions.
func (s *OrgPermissionsService) DeletePermission(ctx context.Context, input api.DeleteOrgPermissionInput) error {
	if err := validateOrgID(input.PermissionID); err != nil {
		return err
	}
	return s.withMutation(ctx, input.Actor, "goauth.org.permissions.delete", func(ctx context.Context) error {
		p, err := s.permissions.PermissionByID(ctx, input.Actor.OrgID, input.PermissionID)
		if err != nil {
			return err
		}
		if p == nil {
			return domain.ErrOrgPermissionNotFound
		}
		if p.IsSystem {
			return domain.ErrProtectedOrgPermission
		}
		if err := s.delegation(ctx, input.Actor, "", []string{p.Key}); err != nil {
			return err
		}
		if p.Revision != input.ExpectedRevision {
			return domain.ErrOrgAuthorizationConflict
		}
		roles, err := s.definitions.PermissionGrantRoles(ctx, input.Actor.OrgID, p.ID)
		if err != nil {
			return err
		}
		if len(roles) > 0 {
			return domain.ErrOrgPermissionInUse
		}
		if err := s.definitions.DeleteOrgPermission(ctx, input.Actor.OrgID, p.ID); err != nil {
			return err
		}
		return s.record(ctx, input.Actor, audit.EventOrgPermissionDeleted, map[string]any{"permissionId": p.ID, "key": p.Key})
	})
}

// ListPermissions queries installed records for authorized role editors.
func (s *OrgPermissionsService) ListPermissions(ctx context.Context, input api.ListOrgPermissionsInput) ([]domain.OrgPermission, error) {
	if err := s.require(ctx, input.Actor, "goauth.org.permissions.read"); err != nil {
		return nil, err
	}
	limit, err := orgPage(input.Limit, input.Offset)
	if err != nil {
		return nil, err
	}
	return s.permissions.ListOrgPermissions(ctx, input.Actor.OrgID, limit, input.Offset)
}
