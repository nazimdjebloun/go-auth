package service

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

type orgOperationContextKey struct{}

// AttachOrgService shares the existing ownership/counter transaction helpers.
func (s *OrgPermissionsService) AttachOrgService(org *OrgService) { s.orgSvc = org }

func orgOperationAuthorized(ctx context.Context, orgID string) bool {
	scope, ok := ctx.Value(orgOperationContextKey{}).(string)
	return ok && scope == orgID
}
func orgActor(orgID, userID, sessionID string) api.OrgPermissionActor {
	return api.OrgPermissionActor{OrgID: orgID, UserID: userID, SessionID: sessionID}
}

func runOrgRead[T any](ctx context.Context, s *OrgPermissionsService, actor api.OrgPermissionActor, key string, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	if err := s.require(ctx, actor, key); err != nil {
		return zero, err
	}
	return fn(context.WithValue(ctx, orgOperationContextKey{}, actor.OrgID))
}
func runOrgMutation[T any](ctx context.Context, s *OrgPermissionsService, actor api.OrgPermissionActor, key string, fn func(context.Context) (T, error)) (T, error) {
	var result T
	err := s.withMutation(ctx, actor, key, func(ctx context.Context) error {
		var err error
		result, err = fn(context.WithValue(ctx, orgOperationContextKey{}, actor.OrgID))
		return err
	})
	return result, err
}
func runOrgMutationVoid(ctx context.Context, s *OrgPermissionsService, actor api.OrgPermissionActor, key string, fn func(context.Context) error) error {
	_, err := runOrgMutation(ctx, s, actor, key, func(ctx context.Context) (struct{}, error) { return struct{}{}, fn(ctx) })
	return err
}

func (s *OrgService) requireMemberMutation(ctx context.Context, orgID string, actor *domain.OrgMember, minimum domain.OrgRole) error {
	if !orgOperationAuthorized(ctx, orgID) || minimum == domain.OrgRoleOwner {
		return requireOrgRole(actor, minimum)
	}
	if actor == nil {
		return domain.ErrOrgMemberNotFound
	}
	return nil
}

func (s *OrgPermissionsService) authorizeFixedAssignment(ctx context.Context, actor api.OrgPermissionActor, userID string, next domain.OrgRole) error {
	_, held, err := s.current(ctx, actor)
	if err != nil {
		return err
	}
	if held.IsOwner() {
		return nil
	}
	if userID == actor.UserID || next == domain.OrgRoleOwner {
		return domain.ErrOrgForbidden
	}
	old, _, err := s.roles.MemberRole(ctx, actor.OrgID, userID)
	if err != nil {
		return err
	}
	if old == nil {
		member, err := s.orgs.LockMembership(ctx, actor.OrgID, userID)
		if err != nil {
			return err
		}
		if member != nil {
			old, err = s.roles.RoleBySlug(ctx, actor.OrgID, string(member.Role))
			if err != nil {
				return err
			}
			if old == nil {
				return domain.ErrOrgRoleNotFound
			}
		}
	}
	keys := orgPreset(string(next))
	if old != nil {
		oldKeys, err := s.explicitKeys(ctx, actor.OrgID, old)
		if err != nil {
			return err
		}
		keys = append(keys, oldKeys...)
	}
	return s.delegation(ctx, actor, "", keys)
}
