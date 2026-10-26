package service

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
)

func validateOrgLibraryBatch(input api.UpdateOrgLibraryPermissionsInput) error {
	if n := len(input.Create) + len(input.Delete); n == 0 || n > 100 {
		return orgInvalid("Supply 1..100 permission keys across create/delete")
	}
	seen := map[string]bool{}
	for _, keys := range [][]string{input.Create, input.Delete} {
		for _, key := range keys {
			if err := validateOrgKey(key); err != nil {
				return err
			}
			if _, known := orgLibraryDefinition(key); !known {
				return domain.ErrUnknownLibraryPermission
			}
			if seen[key] {
				return orgInvalid("Permission keys must be unique across create/delete")
			}
			seen[key] = true
		}
	}
	return nil
}

// UpdateLibraryPermissions lets an owner install or remove known delegation definitions.
func (s *OrgPermissionsService) UpdateLibraryPermissions(ctx context.Context, input api.UpdateOrgLibraryPermissionsInput) (*api.UpdateOrgLibraryPermissionsResult, error) {
	if err := validateOrgID(input.Actor.OrgID); err != nil {
		return nil, err
	}
	if err := validateOrgLibraryBatch(input); err != nil {
		return nil, err
	}
	result := &api.UpdateOrgLibraryPermissionsResult{Created: []string{}, Deleted: []string{}, Unchanged: []string{}}
	err := s.users.WithAdminGuard(ctx, func(ctx context.Context) error {
		if err := s.state.LockOrg(ctx, input.Actor.OrgID); err != nil {
			return err
		}
		ctx = context.WithValue(ctx, orgManagementContextKey{}, input.Actor.OrgID)
		if err := s.RequireOwner(ctx, input.Actor); err != nil {
			return err
		}
		now := time.Now().UTC()
		affectedRoles := map[string]bool{}
		removedGrants := map[string][]string{}
		for _, keys := range [][]string{input.Create, input.Delete} {
			for _, key := range keys {
				p, err := s.permissions.PermissionByKey(ctx, input.Actor.OrgID, key)
				if err != nil {
					return err
				}
				if p != nil {
					d, _ := orgLibraryDefinition(key)
					if !p.IsSystem || !p.IsEnabled || p.Name != d.Name || p.Description != d.Description {
						return fmt.Errorf("library catalog integrity mismatch for %s", key)
					}
				}
			}
		}
		for _, key := range input.Create {
			p, err := s.permissions.PermissionByKey(ctx, input.Actor.OrgID, key)
			if err != nil {
				return err
			}
			if p != nil {
				result.Unchanged = append(result.Unchanged, key)
				continue
			}
			d, _ := orgLibraryDefinition(key)
			p = &domain.OrgPermission{OrgID: input.Actor.OrgID, ID: uuid.NewString(), Key: key, Name: d.Name, Description: d.Description, IsEnabled: true, IsSystem: true, Revision: 1, CreatedAt: now, UpdatedAt: now}
			if err := s.definitions.InsertOrgPermission(ctx, p); err != nil {
				return err
			}
			result.Created = append(result.Created, key)
		}
		for _, key := range input.Delete {
			p, err := s.permissions.PermissionByKey(ctx, input.Actor.OrgID, key)
			if err != nil {
				return err
			}
			if p == nil {
				result.Unchanged = append(result.Unchanged, key)
				continue
			}
			roles, err := s.definitions.PermissionGrantRoles(ctx, input.Actor.OrgID, p.ID)
			if err != nil {
				return err
			}
			removedGrants[key] = roles
			for _, id := range roles {
				affectedRoles[id] = true
			}
			if err := s.definitions.RemovePermissionGrants(ctx, input.Actor.OrgID, p.ID); err != nil {
				return err
			}
			if err := s.definitions.DeleteOrgPermission(ctx, input.Actor.OrgID, p.ID); err != nil {
				return err
			}
			result.Deleted = append(result.Deleted, key)
		}
		ids := make([]string, 0, len(affectedRoles))
		for id := range affectedRoles {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			if err := s.roles.BumpRoleRevision(ctx, input.Actor.OrgID, id, now); err != nil {
				return err
			}
		}
		slices.Sort(result.Created)
		slices.Sort(result.Deleted)
		slices.Sort(result.Unchanged)
		if len(result.Created)+len(result.Deleted) == 0 {
			return nil
		}
		if err := s.state.BumpOrgState(ctx, input.Actor.OrgID); err != nil {
			return err
		}
		return s.record(ctx, input.Actor, audit.EventOrgLibraryPermissionsChanged, map[string]any{"created": result.Created, "deleted": result.Deleted, "removedGrants": removedGrants, "source": "runtime"})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
