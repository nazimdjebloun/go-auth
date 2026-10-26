package service

import (
	"context"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
)

func (s *OrgInviteService) createPermissionInvite(ctx context.Context, input api.CreateOrgInviteInput) (*domain.OrgInvite, error) {
	if s.inviteTTL <= 0 {
		return nil, domain.ErrInternal
	}
	if s.mailer == nil {
		return nil, domain.ErrEmailNotConfigured
	}
	if input.OrgRoleID != "" && input.Role != "" {
		return nil, orgInvalid("Supply role or orgRoleId, not both")
	}
	if input.OrgRoleID == "" && !input.Role.IsValid() {
		return nil, domain.ErrInvalidOrgRole
	}
	if input.OrgRoleID != "" {
		if err := validateOrgID(input.OrgRoleID); err != nil {
			return nil, err
		}
	}
	raw, err := s.gen.Generate()
	if err != nil {
		return nil, domain.ErrInternal
	}
	actor := orgActor(input.OrgID, input.InvitedBy, input.ActorSessionID)
	var invite *domain.OrgInvite
	err = s.orgPermissions.withMutation(ctx, actor, "goauth.org.invites.create", func(ctx context.Context) error {
		var role *domain.OrgPermissionRole
		var err error
		if input.OrgRoleID != "" {
			if err = s.orgPermissions.require(ctx, actor, "goauth.org.roles.assign"); err != nil {
				return err
			}
			role, err = s.orgPermissions.roles.RoleByID(ctx, input.OrgID, input.OrgRoleID)
		} else {
			role, err = s.orgPermissions.roles.RoleBySlug(ctx, input.OrgID, string(input.Role))
		}
		if err != nil {
			return err
		}
		if role == nil || !role.IsEnabled {
			return domain.ErrOrgRoleNotFound
		}
		if input.OrgRoleID != "" && role.Revision != input.ExpectedRoleRevision {
			return domain.ErrOrgAuthorizationConflict
		}
		if err = s.orgPermissions.authorizeInviteRole(ctx, actor, role); err != nil {
			return err
		}
		base := domain.OrgRoleMember
		if role.SystemKey != nil {
			base = domain.OrgRole(*role.SystemKey)
		}
		now := time.Now().UTC()
		invite = &domain.OrgInvite{ID: generateID(), OrgID: input.OrgID, Email: strings.ToLower(strings.TrimSpace(input.Email)), Role: base, OrgRoleID: &role.ID, OrgRoleRevision: role.Revision, CodeHash: hashToken(raw), RawCode: raw, InvitedBy: input.InvitedBy, ExpiresAt: now.Add(s.inviteTTL), CreatedAt: now}
		if err = s.orgInvites.Create(ctx, invite); err != nil {
			return err
		}
		if err = s.orgPermissions.roles.SetInviteRole(ctx, input.OrgID, invite.ID, role.ID, role.Revision); err != nil {
			return err
		}
		return s.orgPermissions.record(ctx, actor, audit.EventOrgInviteCreated, map[string]any{"inviteId": invite.ID, "roleId": role.ID})
	})
	if err != nil {
		return nil, err
	}
	if err = s.sendOrgInviteEmail(ctx, invite); err != nil {
		return nil, domain.ErrInviteEmailFailed
	}
	return invite, nil
}

func (s *OrgPermissionsService) authorizeInviteRole(ctx context.Context, actor api.OrgPermissionActor, role *domain.OrgPermissionRole) error {
	_, held, err := s.current(ctx, actor)
	if err != nil {
		return err
	}
	if role.IsOwner() && !held.IsOwner() {
		return domain.ErrOrgForbidden
	}
	keys, err := s.explicitKeys(ctx, actor.OrgID, role)
	if err != nil {
		return err
	}
	return s.delegation(ctx, actor, "", keys)
}

// acceptPermissionInvite reads the proposed role before the claim cascades its
// snapshot away. Changes to the role or inviter revoke the pending delegation.
func (s *OrgInviteService) acceptPermissionInvite(ctx context.Context, input api.AcceptInviteInput, invite *domain.OrgInvite, codeHash string) error {
	return s.users.WithAdminGuard(ctx, func(ctx context.Context) error {
		if err := s.orgPermissions.state.LockOrg(ctx, invite.OrgID); err != nil {
			return err
		}
		ctx = context.WithValue(ctx, orgManagementContextKey{}, invite.OrgID)
		user, err := s.users.GetByIDForUpdate(ctx, input.UserID)
		if err != nil {
			return err
		}
		if user == nil || user.IsBanned {
			return domain.ErrOrgForbidden
		}
		if !strings.EqualFold(user.Email, invite.Email) {
			return domain.ErrOrgInviteEmailMismatch
		}
		role, revision, err := s.orgPermissions.roles.InviteRole(ctx, invite.OrgID, invite.ID)
		if err != nil {
			return err
		}
		if role == nil {
			role, err = s.orgPermissions.roles.RoleBySlug(ctx, invite.OrgID, string(invite.Role))
			if err != nil {
				return err
			}
			if role == nil {
				return domain.ErrOrgPermissionsNotInitialized
			}
			revision = role.Revision
		}
		if !role.IsEnabled || role.Revision != revision {
			return domain.ErrOrgInviteRoleChanged
		}
		actor := orgActor(invite.OrgID, invite.InvitedBy, "")
		// This is an existing durable delegation, not a new authenticated
		// request by the inviter. Check current membership/grants without
		// requiring their original session to remain alive.
		if err := s.orgPermissions.requireInvitationAuthority(ctx, actor, role); err != nil {
			return err
		}
		base := domain.OrgRoleMember
		if role.SystemKey != nil {
			base = domain.OrgRole(*role.SystemKey)
		}
		claimed, err := s.orgInvites.ClaimInvite(ctx, invite.ID, codeHash)
		if err != nil {
			return err
		}
		if !claimed {
			return domain.ErrOrgInviteExpired
		}
		if base == domain.OrgRoleOwner {
			if err = s.orgs.IncrementUserOrgOwnerCount(ctx, input.UserID, s.maxOrgs); err != nil {
				return err
			}
			if err = s.orgs.IncrementOrgOwnerCount(ctx, invite.OrgID); err != nil {
				return err
			}
		}
		if err = s.orgs.IncrementOrgMemberCount(ctx, invite.OrgID, 10000); err != nil {
			return err
		}
		if err = s.orgs.AddMember(ctx, &domain.OrgMember{OrgID: invite.OrgID, UserID: input.UserID, Role: base, JoinedAt: time.Now().UTC()}); err != nil {
			return err
		}
		changed, err := s.orgPermissions.roles.SetMemberRole(ctx, invite.OrgID, input.UserID, role.ID, 0)
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrOrgAuthorizationConflict
		}
		return s.orgPermissions.record(ctx, orgActor(invite.OrgID, input.UserID, ""), audit.EventOrgInviteAccepted, map[string]any{"roleId": role.ID, "inviteId": invite.ID})
	})
}

func (s *OrgPermissionsService) requireInvitationAuthority(ctx context.Context, actor api.OrgPermissionActor, role *domain.OrgPermissionRole) error {
	_, held, err := s.current(ctx, actor)
	if err != nil {
		return err
	}
	keys, err := s.effectiveKeys(ctx, actor.OrgID, held, true)
	if err != nil {
		return err
	}
	if !containsOrgKey(keys, "goauth.org.invites.create") {
		return domain.ErrOrgForbidden
	}
	if role.SystemKey == nil && !containsOrgKey(keys, "goauth.org.roles.assign") {
		return domain.ErrOrgForbidden
	}
	return s.authorizeInviteRole(ctx, actor, role)
}
func containsOrgKey(keys []string, key string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

func (s *OrgInviteService) resendPermissionInvite(ctx context.Context, input api.ResendOrgInviteEmailInput) error {
	if s.mailer == nil {
		return domain.ErrEmailNotConfigured
	}
	raw, err := s.gen.Generate()
	if err != nil {
		return domain.ErrInternal
	}
	actor := orgActor(input.OrgID, input.ActorID, input.ActorSessionID)
	var invite *domain.OrgInvite
	err = s.orgPermissions.withMutation(ctx, actor, "goauth.org.invites.resend", func(ctx context.Context) error {
		var err error
		invite, err = s.orgInvites.GetByID(ctx, input.InviteID)
		if err != nil {
			return err
		}
		if invite == nil || invite.OrgID != input.OrgID {
			return domain.ErrInviteNotFound
		}
		role, revision, err := s.orgPermissions.roles.InviteRole(ctx, input.OrgID, input.InviteID)
		if err != nil {
			return err
		}
		if role != nil {
			if !role.IsEnabled || role.Revision != revision {
				return domain.ErrOrgInviteRoleChanged
			}
			if err = s.orgPermissions.requireInvitationAuthority(ctx, orgActor(input.OrgID, invite.InvitedBy, ""), role); err != nil {
				return err
			}
		}
		invite.CodeHash = hashToken(raw)
		invite.RawCode = raw
		invite.ExpiresAt = time.Now().UTC().Add(s.inviteTTL)
		if err = s.orgInvites.Update(ctx, invite); err != nil {
			return err
		}
		return s.orgPermissions.record(ctx, actor, audit.EventOrgInviteResent, map[string]any{"inviteId": invite.ID})
	})
	if err != nil {
		return err
	}
	if err = s.sendOrgInviteEmail(ctx, invite); err != nil {
		return domain.ErrInviteEmailFailed
	}
	return nil
}
