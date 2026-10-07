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

// UpdateLibraryPermissions is protected-admin-only, independent of delegable keys.
func (s *AppPermissionsService) UpdateLibraryPermissions(ctx context.Context, input api.UpdateAppLibraryPermissionsInput) (*api.UpdateAppLibraryPermissionsResult, error) {
	return s.updateLibraryPermissions(ctx, input, true, "runtime")
}

// AppLibraryPermissionCLIProvisioner is only reachable inside the module's CLI.
// Database administration has a separate trust boundary from HTTP authentication.
type AppLibraryPermissionCLIProvisioner struct{ service *AppPermissionsService }

// NewAppLibraryPermissionCLIProvisioner shares the service's private transaction writer.
func NewAppLibraryPermissionCLIProvisioner(s *AppPermissionsService) *AppLibraryPermissionCLIProvisioner {
	return &AppLibraryPermissionCLIProvisioner{service: s}
}

// Update verifies a current protected actor and records local-CLI attribution.
func (p *AppLibraryPermissionCLIProvisioner) Update(ctx context.Context, input api.UpdateAppLibraryPermissionsInput) (*api.UpdateAppLibraryPermissionsResult, error) {
	return p.service.updateLibraryPermissions(ctx, input, false, "cli")
}

func validateLibraryBatch(input api.UpdateAppLibraryPermissionsInput) error {
	if n := len(input.Create) + len(input.Delete); n == 0 || n > 100 {
		return appInvalid("Supply 1..100 permission keys across create/delete")
	}
	seen := map[string]bool{}
	for _, keys := range [][]string{input.Create, input.Delete} {
		for _, key := range keys {
			if err := validateAppKey(key); err != nil {
				return err
			}
			if _, known := appLibraryDefinition(key); !known {
				return domain.ErrUnknownLibraryPermission
			}
			if seen[key] {
				return appInvalid("Permission keys must be unique across create/delete")
			}
			seen[key] = true
		}
	}
	return nil
}

func (s *AppPermissionsService) updateLibraryPermissions(ctx context.Context, input api.UpdateAppLibraryPermissionsInput, checkAssurance bool, source string) (*api.UpdateAppLibraryPermissionsResult, error) {
	if err := validateLibraryBatch(input); err != nil {
		return nil, err
	}
	result := &api.UpdateAppLibraryPermissionsResult{Created: []string{}, Deleted: []string{}, Unchanged: []string{}}
	err := s.users.WithAdminGuard(ctx, func(ctx context.Context) error {
		if err := s.state.LockAppState(ctx); err != nil {
			return err
		}
		ctx = context.WithValue(ctx, appManagementContextKey{}, true)
		if err := s.requireProtectedAdmin(ctx, input.Actor, checkAssurance); err != nil {
			return err
		}
		now := time.Now().UTC()
		affectedRoles := map[string]bool{}
		removedGrants := map[string][]string{}
		for _, keys := range [][]string{input.Create, input.Delete} {
			for _, key := range keys {
				p, err := s.permissions.PermissionByKey(ctx, key)
				if err != nil {
					return err
				}
				if p != nil {
					d, _ := appLibraryDefinition(key)
					if !p.IsSystem || !p.IsEnabled || p.Name != d.Name || p.Description != d.Description {
						return fmt.Errorf("library catalog integrity mismatch for %s", key)
					}
				}
			}
		}
		for _, key := range input.Create {
			p, err := s.permissions.PermissionByKey(ctx, key)
			if err != nil {
				return err
			}
			if p != nil {
				result.Unchanged = append(result.Unchanged, key)
				continue
			}
			d, _ := appLibraryDefinition(key)
			p = &domain.AppPermission{ID: uuid.NewString(), Key: key, Name: d.Name, Description: d.Description, IsEnabled: true, IsSystem: true, Revision: 1, CreatedAt: now, UpdatedAt: now}
			if err := s.definitions.InsertAppPermission(ctx, p); err != nil {
				return err
			}
			result.Created = append(result.Created, key)
		}
		for _, key := range input.Delete {
			p, err := s.permissions.PermissionByKey(ctx, key)
			if err != nil {
				return err
			}
			if p == nil {
				result.Unchanged = append(result.Unchanged, key)
				continue
			}
			roles, err := s.definitions.PermissionGrantRoles(ctx, p.ID)
			if err != nil {
				return err
			}
			removedGrants[key] = roles
			for _, id := range roles {
				affectedRoles[id] = true
			}
			if err := s.definitions.RemovePermissionGrants(ctx, p.ID); err != nil {
				return err
			}
			if err := s.definitions.DeleteAppPermission(ctx, p.ID); err != nil {
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
			if err := s.roles.BumpRoleRevision(ctx, id, now); err != nil {
				return err
			}
		}
		slices.Sort(result.Created)
		slices.Sort(result.Deleted)
		slices.Sort(result.Unchanged)
		if len(result.Created)+len(result.Deleted) == 0 {
			return nil
		}
		if err := s.state.BumpAppState(ctx); err != nil {
			return err
		}
		return s.record(ctx, input.Actor, audit.EventAppLibraryPermissionsChanged, map[string]any{"created": result.Created, "deleted": result.Deleted, "removedGrants": removedGrants, "source": source})
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
