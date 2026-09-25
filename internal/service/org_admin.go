package service

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// Platform-admin oversight of organizations.
//
// Everything in this file is a platform-admin operation — gated by requireAdminRole
// (is the caller a platform admin?), not requireRole (is the caller a member
// of this specific org?). These exist because org self-service has no
// concept of a platform operator: today, nobody outside an org's own
// membership can list it, view it, or intervene in it, however malformed or
// abandoned it becomes. Each mutating method reuses the same tx helper as
// its self-service counterpart (deleteOrgTx, addMemberTx, removeMemberTx,
// updateMemberRoleTx) so repository-level invariants — e.g. "can't remove
// the last owner" — still apply to an admin override. What's bypassed is
// authorization only, plus (deliberately, for UpdateMemberRole only) the
// same-org owner-escalation guard, which exists to stop a same-org Admin
// self-promoting and has no bearing on a platform admin acting from outside
// the org. Every method here publishes its own admin.org.* audit event,
// distinct from the organization.* events the self-service paths publish,
// so "the owner deleted their org" and "a platform admin force-deleted it"
// never look identical in the audit log.

// AdminListOrgs lists every organization on the platform, filterable by
// name/slug search and creation-date range — the cross-org counterpart to
// ListUserOrgs, which is scoped to one user's memberships.
func (s *OrgService) AdminListOrgs(ctx context.Context, input api.AdminListOrgsInput) (*api.AdminListOrgsResult, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return nil, err
	}
	limit := 20
	if input.Limit != nil {
		limit = *input.Limit
		if limit < 0 {
			limit = 20
		} else if limit > 100 {
			limit = 100
		}
	}
	orgs, err := s.orgs.List(ctx, port.OrgFilter{
		Search:         input.Search,
		CreatedAfter:   input.CreatedAfter,
		CreatedBefore:  input.CreatedBefore,
		OrderBy:        input.OrderBy,
		OrderDirection: input.OrderDirection,
		Offset:         input.Offset,
		Limit:          limit,
	})
	if err != nil {
		return nil, err
	}
	if orgs == nil {
		orgs = []domain.Organization{}
	}
	return &api.AdminListOrgsResult{Orgs: orgs, Limit: limit, Offset: input.Offset}, nil
}

// CountOrgs returns how many organizations match the input's filters
// (pagination ignored).
func (s *OrgService) CountOrgs(ctx context.Context, input api.AdminListOrgsInput) (int, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return 0, err
	}
	return s.orgs.Count(ctx, port.OrgFilter{
		Search:        input.Search,
		CreatedAfter:  input.CreatedAfter,
		CreatedBefore: input.CreatedBefore,
	})
}

// CountMembers returns how many members of the org match the input's filters.
func (s *OrgService) CountMembers(ctx context.Context, input api.ListMembersInput) (int, error) {
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleMember); err != nil {
		return 0, err
	}
	return s.orgs.CountMembers(ctx, input.OrgID, port.OrgMemberFilter{
		Role:   input.Role,
		Search: input.Search,
	})
}

// CountUserOrgs returns how many orgs the user belongs to that match search/role.
func (s *OrgService) CountUserOrgs(ctx context.Context, input api.ListUserOrgsInput) (int, error) {
	return s.orgs.CountUserOrgs(ctx, input.UserID, port.UserOrgFilter{Search: input.Search, Role: input.Role})
}

// AdminListUserOrgs returns a user's organizations to an administrator.
func (s *OrgService) AdminListUserOrgs(ctx context.Context, input api.AdminListUserOrgsInput) (*api.ListUserOrgsResult, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return nil, err
	}
	// GetByID reports a missing row as (nil, nil), so the nil check is what
	// actually produces the 404 — an err-only check would list orgs for a
	// user that doesn't exist and return an empty page instead.
	if user, err := s.users.GetByID(ctx, input.UserID); err != nil || user == nil {
		return nil, domain.ErrUserNotFound
	}
	limit := 20
	if input.Limit != nil {
		limit = *input.Limit
		if limit < 0 {
			limit = 20
		} else if limit > 100 {
			limit = 100
		}
	}
	orgs, err := s.orgs.ListUserOrgs(ctx, input.UserID, port.UserOrgFilter{
		Search:         input.Search,
		Role:           input.Role,
		OrderBy:        input.OrderBy,
		OrderDirection: input.OrderDirection,
		Offset:         input.Offset,
		Limit:          limit,
	})
	if err != nil {
		return nil, err
	}
	if orgs == nil {
		orgs = []domain.Organization{}
	}
	return &api.ListUserOrgsResult{Orgs: orgs, Limit: limit, Offset: input.Offset}, nil
}

// AdminCountUserOrgs returns a user's organization count to an administrator.
func (s *OrgService) AdminCountUserOrgs(ctx context.Context, input api.AdminListUserOrgsInput) (int, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return 0, err
	}
	if user, err := s.users.GetByID(ctx, input.UserID); err != nil || user == nil {
		return 0, domain.ErrUserNotFound
	}
	return s.orgs.CountUserOrgs(ctx, input.UserID, port.UserOrgFilter{Search: input.Search, Role: input.Role})
}

// AdminGetOrg fetches one organization regardless of the caller's membership
// in it. Publishes EventAdminOrgViewed: this exposes an org's metadata to
// platform staff who may not be members, and that access itself is worth an
// audit trail entry.
func (s *OrgService) AdminGetOrg(ctx context.Context, input api.AdminGetOrgInput) (*domain.Organization, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return nil, err
	}
	org, err := s.orgs.GetByID(ctx, input.OrgID)
	if err != nil {
		s.log.Error("failed to get org (admin)", "err", err, "org_id", input.OrgID)
		return nil, err
	}
	if org == nil {
		return nil, domain.ErrOrgNotFound
	}

	if s.audit != nil {
		if err := s.audit.Record(ctx, audit.NewOrgEvent(audit.EventAdminOrgViewed, input.ActorID, input.OrgID, nil)); err != nil {
			return nil, err
		}
	}

	return org, nil
}

// AdminListOrgMembers lists orgID's members regardless of the caller's own
// membership in it — the admin-bypass counterpart to ListMembers, which
// requires the caller to already be a member. Publishes EventAdminOrgViewed
// for the same reason as AdminGetOrg: this is cross-tenant member data
// (emails, roles) being exposed to platform staff.
func (s *OrgService) AdminListOrgMembers(ctx context.Context, input api.AdminListOrgMembersInput) (*api.ListMembersResult, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return nil, err
	}
	limit := 20
	if input.Limit != nil {
		limit = *input.Limit
		if limit < 0 {
			limit = 20
		} else if limit > 100 {
			limit = 100
		}
	}
	members, err := s.orgs.ListMembers(ctx, input.OrgID, port.OrgMemberFilter{
		Role:           input.Role,
		Search:         input.Search,
		OrderBy:        input.OrderBy,
		OrderDirection: input.OrderDirection,
		Offset:         input.Offset,
		Limit:          limit,
	})
	if err != nil {
		return nil, err
	}
	if members == nil {
		members = []domain.OrgMemberDetail{}
	}

	if s.audit != nil {
		if err := s.audit.Record(ctx, audit.NewOrgEvent(audit.EventAdminOrgViewed, input.ActorID, input.OrgID, nil)); err != nil {
			return nil, err
		}
	}

	return &api.ListMembersResult{Members: members, Limit: limit, Offset: input.Offset}, nil
}

// AdminCountOrgMembers returns how many of orgID's members match the input's
// filters, bypassing the membership check (admin oversight). Pagination is
// ignored. Unlike AdminListOrgMembers it publishes no audit event — it
// exposes only a count, not member data.
func (s *OrgService) AdminCountOrgMembers(ctx context.Context, input api.AdminListOrgMembersInput) (int, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return 0, err
	}
	return s.orgs.CountMembers(ctx, input.OrgID, port.OrgMemberFilter{
		Role:   input.Role,
		Search: input.Search,
	})
}

// AdminDeleteOrg force-deletes orgID regardless of whether the caller is a
// member of it. Publishes EventAdminOrgDeleted — distinct from the
// self-service EventOrgDeleted — with the org's name/slug snapshotted into
// the event metadata, since the organizations row won't survive the delete
// for anything to join against later.
func (s *OrgService) AdminDeleteOrg(ctx context.Context, input api.AdminOrgActionInput) error {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return err
	}
	_, err := s.deleteOrgTx(ctx, input.OrgID, func(txCtx context.Context, org *domain.Organization) error {
		if s.audit == nil {
			return nil
		}
		evt := audit.NewOrgEvent(audit.EventAdminOrgDeleted, input.ActorID, input.OrgID, nil)
		evt.Metadata = map[string]any{"orgName": org.Name, "orgSlug": org.Slug, "override": true}
		return s.audit.Record(txCtx, evt)
	})
	return err
}

// AdminAddMember force-adds userID to orgID with the given role, regardless
// of the caller's own membership. This is the recovery path for an org
// whose only owner left or was removed and is otherwise unmanageable by
// anyone — AdminRemoveMember/AdminUpdateMemberRole alone can't fix that,
// since both require the target to already be a member. Publishes
// EventAdminOrgMemberAdded.
func (s *OrgService) AdminAddMember(ctx context.Context, input api.AdminAddMemberInput) error {
	if !input.Role.IsValid() {
		return domain.ErrInvalidOrgRole
	}
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return err
	}
	return s.addMemberTx(ctx, input.OrgID, input.UserID, input.Role, func(txCtx context.Context) error {
		if s.audit == nil {
			return nil
		}
		return s.audit.Record(txCtx, audit.NewOrgEvent(audit.EventAdminOrgMemberAdded, input.ActorID, input.OrgID, &input.UserID))
	})
}

// AdminRemoveMember force-removes userID from orgID regardless of the
// caller's own membership. Publishes EventAdminOrgMemberRemoved — distinct
// from the self-service EventOrgMemberRemoved.
func (s *OrgService) AdminRemoveMember(ctx context.Context, input api.AdminRemoveMemberInput) error {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return err
	}
	_, err := s.removeMemberTx(ctx, input.OrgID, input.UserID, func(txCtx context.Context, _ domain.OrgRole) error {
		if s.audit == nil {
			return nil
		}
		return s.audit.Record(txCtx, audit.NewOrgEvent(audit.EventAdminOrgMemberRemoved, input.ActorID, input.OrgID, &input.UserID))
	})
	return err
}

// AdminUpdateMemberRole force-changes userID's role within orgID, including
// granting or revoking Owner — the self-service UpdateMemberRole's
// owner-escalation guard (only an Owner can touch the Owner role) is
// deliberately not applied here: that guard exists to stop a same-org Admin
// self-promoting, and doesn't apply to a platform admin acting from outside
// the org. Publishes EventAdminOrgMemberRoleChanged.
func (s *OrgService) AdminUpdateMemberRole(ctx context.Context, input api.AdminUpdateMemberRoleInput) error {
	if !input.NewRole.IsValid() {
		return domain.ErrInvalidOrgRole
	}
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return err
	}
	oldRole, err := s.updateMemberRoleTx(ctx, input.OrgID, input.UserID, input.NewRole, func(txCtx context.Context, _ domain.OrgRole) error {
		if s.audit == nil {
			return nil
		}
		return s.audit.Record(txCtx, audit.NewOrgEvent(audit.EventAdminOrgMemberRoleChanged, input.ActorID, input.OrgID, &input.UserID))
	})
	if err != nil {
		return err
	}
	if oldRole == "" {
		return nil // no-op: already had this role
	}

	return nil
}
