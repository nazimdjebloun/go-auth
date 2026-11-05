package service

import (
	"context"
	"fmt"

	"github.com/nazimdjebloun/go-auth/domain"
)

// Fixed invitations are durable delegations. Hold current membership authority
// until the write/claim commits, in the same users-before-memberships order as
// role changes, removals and granular invitation management.
func (s *OrgInviteService) withFixedInviteMutation(ctx context.Context, fn func(context.Context) error) error {
	return s.txManager.WithTx(ctx, func(ctx context.Context) error {
		return s.users.WithAdminGuard(ctx, fn)
	})
}

func (s *OrgInviteService) requireFixedInviteAuthority(ctx context.Context, orgID, actorID string, role domain.OrgRole) error {
	if actorID == "" || !role.IsValid() {
		return domain.ErrOrgForbidden
	}
	user, err := s.users.GetByIDForUpdate(ctx, actorID)
	if err != nil {
		return fmt.Errorf("loading fixed invitation issuer: %w", err)
	}
	if user == nil || user.IsBanned {
		return domain.ErrOrgForbidden
	}
	member, err := s.orgs.LockMembership(ctx, orgID, actorID)
	if err != nil {
		return err
	}
	if member == nil || member.Role.Weight() < domain.OrgRoleAdmin.Weight() ||
		(role == domain.OrgRoleOwner && member.Role != domain.OrgRoleOwner) {
		return domain.ErrOrgForbidden
	}
	return nil
}
