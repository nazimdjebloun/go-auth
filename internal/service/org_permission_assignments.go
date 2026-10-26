package service

import (
	"context"
	"slices"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
)

type orgAssigningContextKey struct{}

// SetMemberRole changes exactly one membership, preserving ownership counters.
func (s *OrgPermissionsService) SetMemberRole(ctx context.Context, input api.SetOrgMemberRoleInput) (*api.OrgMemberRoleResult, error) {
	if err := validateOrgID(input.RoleID); err != nil {
		return nil, err
	}
	if err := validateOrgID(input.UserID); err != nil {
		return nil, err
	}
	var result *api.OrgMemberRoleResult
	err := s.withMutation(ctx, input.Actor, "goauth.org.roles.assign", func(ctx context.Context) error {
		target, err := s.orgs.LockMembership(ctx, input.Actor.OrgID, input.UserID)
		if err != nil {
			return err
		}
		if target == nil {
			return domain.ErrOrgMemberNotFound
		}
		old, revision, err := s.roles.MemberRole(ctx, input.Actor.OrgID, input.UserID)
		if err != nil {
			return err
		}
		if revision != input.ExpectedAssignmentRevision {
			return domain.ErrOrgAuthorizationConflict
		}
		if old == nil {
			old, err = s.roles.RoleBySlug(ctx, input.Actor.OrgID, string(target.Role))
			if err != nil {
				return err
			}
		}
		role, err := s.roles.RoleByID(ctx, input.Actor.OrgID, input.RoleID)
		if err != nil {
			return err
		}
		if role == nil || !role.IsEnabled {
			return domain.ErrOrgRoleNotFound
		}
		if role.Revision != input.ExpectedRoleRevision {
			return domain.ErrOrgAuthorizationConflict
		}
		_, actorRole, err := s.current(ctx, input.Actor)
		if err != nil {
			return err
		}
		if !actorRole.IsOwner() && (input.UserID == input.Actor.UserID || target.Role == domain.OrgRoleOwner || role.IsOwner()) {
			return domain.ErrOrgForbidden
		}
		oldKeys, err := s.explicitKeys(ctx, input.Actor.OrgID, old)
		if err != nil {
			return err
		}
		keys, err := s.explicitKeys(ctx, input.Actor.OrgID, role)
		if err != nil {
			return err
		}
		if err := s.delegation(ctx, input.Actor, "", append(slices.Clone(oldKeys), keys...)); err != nil {
			return err
		}
		role.PermissionKeys = keys
		if old.ID == role.ID {
			result = &api.OrgMemberRoleResult{Role: *role, AssignmentRevision: revision}
			return nil
		}
		base := domain.OrgRoleMember
		if role.SystemKey != nil {
			base = domain.OrgRole(*role.SystemKey)
		}
		if s.orgSvc == nil {
			return domain.ErrInternal
		}
		if _, err := s.orgSvc.updateMemberRoleTx(context.WithValue(ctx, orgAssigningContextKey{}, true), input.Actor.OrgID, input.UserID, base, nil); err != nil {
			return err
		}
		changed, err := s.roles.SetMemberRole(ctx, input.Actor.OrgID, input.UserID, role.ID, revision)
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrOrgAuthorizationConflict
		}
		result = &api.OrgMemberRoleResult{Role: *role, AssignmentRevision: revision + 1}
		return s.record(ctx, input.Actor, audit.EventOrgMemberRoleChanged, map[string]any{"userId": input.UserID, "oldRoleId": old.ID, "roleId": role.ID, "assignmentRevision": revision + 1})
	})
	return result, err
}

// GetMemberRole requires roles.read even for self; use ListEffectivePermissions
// for self-inspection without role-management access.
func (s *OrgPermissionsService) GetMemberRole(ctx context.Context, input api.GetOrgMemberRoleInput) (*api.OrgMemberRoleResult, error) {
	if err := validateOrgID(input.UserID); err != nil {
		return nil, err
	}
	if err := s.require(ctx, input.Actor, "goauth.org.roles.read"); err != nil {
		return nil, err
	}
	member, err := s.orgs.GetMembership(ctx, input.Actor.OrgID, input.UserID)
	if err != nil {
		return nil, err
	}
	if member == nil {
		return nil, domain.ErrOrgMemberNotFound
	}
	// The caller is already authorized. A disabled role or banned target must
	// remain inspectable so an authorized manager can review and repair it.
	role, revision, err := s.memberRole(ctx, member)
	if err != nil {
		return nil, err
	}
	role.PermissionKeys, err = s.explicitKeys(ctx, input.Actor.OrgID, role)
	return &api.OrgMemberRoleResult{Role: *role, AssignmentRevision: revision}, err
}

// memberRole loads an assignment without treating the target's eligibility as
// caller authorization. Callers must authorize access before inspecting a target.
func (s *OrgPermissionsService) memberRole(
	ctx context.Context,
	member *domain.OrgMember,
) (*domain.OrgPermissionRole, uint64, error) {
	role, revision, err := s.roles.MemberRole(ctx, member.OrgID, member.UserID)
	if err != nil {
		return nil, 0, err
	}
	if role == nil {
		role, err = s.roles.RoleBySlug(ctx, member.OrgID, string(member.Role))
		if err != nil {
			return nil, 0, err
		}
	}
	if role == nil {
		return nil, 0, domain.ErrOrgPermissionsNotInitialized
	}
	return role, revision, nil
}

func orgRoleMatchesMembership(role *domain.OrgPermissionRole, member *domain.OrgMember) bool {
	if role.SystemKey != nil {
		return *role.SystemKey == string(member.Role)
	}
	return member.Role == domain.OrgRoleMember
}

// resetBuiltinAssignment prevents an old custom assignment from surviving a
// change through the fixed-role API, including a same-classification reset.
func (s *OrgService) resetBuiltinAssignment(ctx context.Context, orgID, userID string, base domain.OrgRole) (map[string]any, error) {
	if s.roleAssignments == nil || ctx.Value(orgAssigningContextKey{}) != nil {
		return nil, nil
	}
	old, revision, err := s.roleAssignments.MemberRole(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	if old == nil {
		return nil, nil
	}
	role, err := s.roleAssignments.RoleBySlug(ctx, orgID, string(base))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, domain.ErrOrgRoleNotFound
	}
	if old.ID == role.ID {
		return nil, nil
	}
	changed, err := s.roleAssignments.SetMemberRole(ctx, orgID, userID, role.ID, revision)
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, domain.ErrOrgAuthorizationConflict
	}
	return map[string]any{"oldRoleId": old.ID, "roleId": role.ID, "assignmentRevision": revision + 1}, nil
}
