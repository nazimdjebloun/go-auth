package service

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type OrgService struct {
	orgs      port.OrgRepository
	users     port.UserRepository
	sessions  port.ActiveOrgSessionStore
	txManager port.TxManager
	maxOrgs   int
	log       *slog.Logger
	audit     AuditPublisher
}

type OrgServiceConfig struct {
	MaxOrgsPerUser int
	Logger         *slog.Logger
	Audit          AuditPublisher
}

func NewOrgService(
	orgs port.OrgRepository,
	users port.UserRepository,
	sessions port.ActiveOrgSessionStore,
	txManager port.TxManager,
	cfg OrgServiceConfig,
) *OrgService {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	resolvedMaxOrgs := resolveMaxOrgsPerUser(cfg.MaxOrgsPerUser)
	return &OrgService{
		orgs:      orgs,
		users:     users,
		sessions:  sessions,
		txManager: txManager,
		maxOrgs:   resolvedMaxOrgs,
		log:       cfg.Logger,
		audit:     cfg.Audit,
	}
}

// guardAndIncrementOwnerCount atomically checks and increments a user's
// org_owner_count against the resolved MaxOrgsPerUser cap.
func (s *OrgService) guardAndIncrementOwnerCount(ctx context.Context, userID string) error {
	return s.orgs.IncrementUserOrgOwnerCount(ctx, userID, s.maxOrgs)
}

// requireRole verifies actorID is a member of orgID with at least min role.
// It mirrors middleware.RequireOrgMember + middleware.RequireOrgRole so the
// same authorization is enforced whether a call arrives over HTTP (already
// pre-checked by that middleware) or directly through this service — this is
// the actual authority, the HTTP middleware is only a fast-fail pre-check.
func (s *OrgService) requireRole(ctx context.Context, orgID, actorID string, min domain.OrgRole) error {
	if actorID == "" {
		return domain.ErrForbidden
	}
	m, err := s.orgs.GetMembership(ctx, orgID, actorID)
	if err != nil {
		return err
	}
	if m == nil {
		return domain.ErrOrgMemberNotFound
	}
	if m.Role.Weight() < min.Weight() {
		return domain.ErrOrgForbidden
	}
	return nil
}

type CreateOrgInput struct {
	Name    string
	Slug    string
	OwnerID string
}

func (s *OrgService) CreateOrg(ctx context.Context, input CreateOrgInput) (*domain.Organization, error) {
	if domain.ReservedOrgSlugs[input.Slug] {
		return nil, domain.ErrOrgSlugReserved
	}
	if len([]byte(input.Slug)) > 255 {
		return nil, domain.NewError("invalid_slug", "Slug must be 255 characters or less")
	}
	if input.Name == "" {
		return nil, domain.NewError("invalid_name", "Organization name is required")
	}

	var org *domain.Organization
	err := s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := s.guardAndIncrementOwnerCount(txCtx, input.OwnerID); err != nil {
			s.log.Warn("org owner limit reached", "user_id", input.OwnerID)
			return err
		}

		existing, err := s.orgs.GetBySlug(txCtx, input.Slug)
		if err != nil {
			return err
		}
		if existing != nil {
			s.log.Warn("org slug conflict", "slug", input.Slug)
			return domain.ErrOrgSlugExists
		}

		now := time.Now().UTC()
		org = &domain.Organization{
			ID:          generateID(),
			Name:        input.Name,
			Slug:        input.Slug,
			CreatedBy:   &input.OwnerID,
			OwnerCount:  1,
			MemberCount: 1,
			Metadata:    make(map[string]interface{}),
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		if err := s.orgs.Create(txCtx, org); err != nil {
			if errors.Is(err, port.ErrDuplicateKey) {
				// The GetBySlug check above lost a race — another request
				// created this slug between the check and this Create.
				return domain.ErrOrgSlugExists
			}
			return err
		}

		if err := s.orgs.AddMember(txCtx, &domain.OrgMember{
			OrgID:    org.ID,
			UserID:   input.OwnerID,
			Role:     domain.OrgRoleOwner,
			JoinedAt: now,
		}); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return nil, err
	}
	s.log.Info("org created", "org_id", org.ID, "slug", org.Slug, "owner_id", input.OwnerID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventOrgCreated, input.OwnerID, org.ID, nil))
	}

	return org, nil
}

type GetOrgInput struct {
	OrgID   string
	ActorID string
}

func (s *OrgService) GetByID(ctx context.Context, input GetOrgInput) (*domain.Organization, error) {
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleMember); err != nil {
		return nil, err
	}
	org, err := s.orgs.GetByID(ctx, input.OrgID)
	if err != nil {
		s.log.Error("failed to get org by id", "err", err, "org_id", input.OrgID)
		return nil, err
	}
	if org == nil {
		return nil, domain.ErrOrgNotFound
	}
	return org, nil
}

type GetOrgBySlugInput struct {
	Slug    string
	ActorID string
}

func (s *OrgService) GetBySlug(ctx context.Context, input GetOrgBySlugInput) (*domain.Organization, error) {
	org, err := s.orgs.GetBySlug(ctx, input.Slug)
	if err != nil {
		s.log.Error("failed to get org by slug", "err", err, "slug", input.Slug)
		return nil, err
	}
	if org == nil {
		return nil, domain.ErrOrgNotFound
	}
	if err := s.requireRole(ctx, org.ID, input.ActorID, domain.OrgRoleMember); err != nil {
		return nil, err
	}
	return org, nil
}

type UpdateOrgInput struct {
	OrgID   string
	Name    *string
	Slug    *string
	ActorID string
}

func (s *OrgService) UpdateOrg(ctx context.Context, input UpdateOrgInput) (*domain.Organization, error) {
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleAdmin); err != nil {
		return nil, err
	}
	org, err := s.orgs.GetByID(ctx, input.OrgID)
	if err != nil {
		s.log.Error("failed to get org for update", "err", err, "org_id", input.OrgID)
		return nil, err
	}
	if org == nil {
		return nil, domain.ErrOrgNotFound
	}

	if input.Slug != nil {
		if domain.ReservedOrgSlugs[*input.Slug] {
			return nil, domain.ErrOrgSlugReserved
		}
		if *input.Slug != org.Slug {
			existing, err := s.orgs.GetBySlug(ctx, *input.Slug)
			if err != nil {
				s.log.Error("failed to check slug conflict", "err", err, "slug", *input.Slug)
				return nil, err
			}
			if existing != nil {
				return nil, domain.ErrOrgSlugExists
			}
			org.Slug = *input.Slug
		}
	}
	if input.Name != nil {
		org.Name = *input.Name
	}

	org.UpdatedAt = time.Now().UTC()
	if err := s.orgs.Update(ctx, org); err != nil {
		s.log.Error("failed to update org", "err", err, "org_id", input.OrgID)
		return nil, err
	}
	s.log.Info("org updated", "org_id", org.ID, "slug", org.Slug)
	return org, nil
}

type DeleteOrgInput struct {
	OrgID   string
	ActorID string
}

// deleteOrgTx does the actual work of deleting orgID — fetch, invariant
// upkeep, cascade, delete — with no authorization check of its own. Callers
// (DeleteOrg for self-service, AdminDeleteOrg for a platform override) each
// do their own auth check and publish their own audit event, so the two
// paths stay distinguishable in the audit log even though they share this
// body. Returns the deleted org (fetched before the delete) so callers can
// snapshot its name/slug into their audit event — the row won't exist to
// look it up afterward.
func (s *OrgService) deleteOrgTx(ctx context.Context, orgID string) (*domain.Organization, error) {
	org, err := s.orgs.GetByID(ctx, orgID)
	if err != nil {
		s.log.Error("failed to get org for deletion", "err", err, "org_id", orgID)
		return nil, err
	}
	if org == nil {
		return nil, domain.ErrOrgNotFound
	}

	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := s.orgs.DecrementOwnerCountForOrgOwners(txCtx, orgID); err != nil {
			return err
		}
		if err := s.sessions.ClearActiveOrgForAllMembers(txCtx, orgID); err != nil {
			return err
		}
		return s.orgs.Delete(txCtx, orgID)
	})
	if err != nil {
		s.log.Error("failed to delete org", "err", err, "org_id", orgID)
		return nil, err
	}
	s.log.Info("org deleted", "org_id", orgID)
	return org, nil
}

func (s *OrgService) DeleteOrg(ctx context.Context, input DeleteOrgInput) error {
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleOwner); err != nil {
		return err
	}
	org, err := s.deleteOrgTx(ctx, input.OrgID)
	if err != nil {
		return err
	}

	if s.audit != nil {
		evt := audit.NewOrgEvent(audit.EventOrgDeleted, input.ActorID, input.OrgID, nil)
		evt.Metadata = map[string]any{"orgName": org.Name, "orgSlug": org.Slug}
		s.audit.Publish(ctx, evt)
	}

	return nil
}

type ListUserOrgsInput struct {
	UserID         string
	Search         *string
	OrderBy        string
	OrderDirection string
	Offset         int
	Limit          *int // nil = default 20; explicit 0 = unlimited; else capped at 100
}

type ListUserOrgsResult struct {
	Orgs   []domain.Organization `json:"orgs"`
	Limit  int                   `json:"limit"`
	Offset int                   `json:"offset"`
}

func (s *OrgService) ListUserOrgs(ctx context.Context, input ListUserOrgsInput) (*ListUserOrgsResult, error) {
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
	return &ListUserOrgsResult{Orgs: orgs, Limit: limit, Offset: input.Offset}, nil
}

type GetOrgMembershipInput struct {
	OrgID  string
	UserID string
}

func (s *OrgService) GetMembership(ctx context.Context, input GetOrgMembershipInput) (*domain.OrgMember, error) {
	m, err := s.orgs.GetMembership(ctx, input.OrgID, input.UserID)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, domain.ErrOrgMemberNotFound
	}
	return m, nil
}

type AddMemberInput struct {
	OrgID   string
	UserID  string
	Role    domain.OrgRole
	ActorID string
}

// AddMember adds input.UserID to input.OrgID. There is no direct HTTP route
// for it — invite acceptance adds members via the repository directly, in
// its own transaction, rather than calling this method — but it is an
// exported method on an exported service and reachable directly as
// auth.Services.Org.AddMember(...), so it enforces the same Admin-or-above
// requirement as the other org-mutating methods.
// addMemberTx does the actual work of adding userID to orgID with role —
// existence check, owner/member-count upkeep, insert — with no authorization
// check of its own. See deleteOrgTx's doc comment for why the tx body and
// the auth check are split across caller and helper.
func (s *OrgService) addMemberTx(ctx context.Context, orgID, userID string, role domain.OrgRole) error {
	membership, err := s.orgs.GetMembership(ctx, orgID, userID)
	if err != nil {
		s.log.Error("failed to check membership", "err", err, "org_id", orgID, "user_id", userID)
		return err
	}
	if membership != nil {
		return domain.ErrOrgMemberExists
	}

	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if role == domain.OrgRoleOwner {
			if err := s.guardAndIncrementOwnerCount(txCtx, userID); err != nil {
				return err
			}
			if err := s.orgs.IncrementOrgOwnerCount(txCtx, orgID); err != nil {
				return err
			}
		}

		if err := s.orgs.IncrementOrgMemberCount(txCtx, orgID, 10000); err != nil {
			return err
		}

		return s.orgs.AddMember(txCtx, &domain.OrgMember{
			OrgID:    orgID,
			UserID:   userID,
			Role:     role,
			JoinedAt: time.Now().UTC(),
		})
	})
	if err != nil {
		return err
	}
	s.log.Info("member added", "org_id", orgID, "user_id", userID, "role", role)
	return nil
}

func (s *OrgService) AddMember(ctx context.Context, input AddMemberInput) error {
	if !input.Role.IsValid() {
		return domain.NewError("invalid_role", "Invalid organization role")
	}
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleAdmin); err != nil {
		return err
	}
	return s.addMemberTx(ctx, input.OrgID, input.UserID, input.Role)
}

type RemoveMemberInput struct {
	OrgID   string
	UserID  string
	ActorID string
}

// RemoveMember removes input.UserID from input.OrgID. input.ActorID must
// either equal input.UserID (a member leaving on their own) or hold at
// least Admin — anything else is removing someone else and requires that
// privilege.
// removeMemberTx does the actual work of removing userID from orgID —
// lookup, owner/member-count upkeep, delete, active-org cleanup — with no
// authorization check of its own. See deleteOrgTx's doc comment for why the
// tx body and the auth check are split across caller and helper. Returns the
// removed member's role for the caller to log/audit.
func (s *OrgService) removeMemberTx(ctx context.Context, orgID, userID string) (domain.OrgRole, error) {
	member, err := s.orgs.GetMembership(ctx, orgID, userID)
	if err != nil {
		s.log.Error("failed to get membership for removal", "err", err, "org_id", orgID, "user_id", userID)
		return "", err
	}
	if member == nil {
		return "", domain.ErrOrgMemberNotFound
	}

	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if member.Role == domain.OrgRoleOwner {
			if err := s.orgs.TryDecrementOrgOwnerCount(txCtx, orgID); err != nil {
				return err
			}
			if err := s.orgs.DecrementUserOrgOwnerCount(txCtx, userID); err != nil {
				return err
			}
		}

		if err := s.orgs.DecrementOrgMemberCount(txCtx, orgID); err != nil {
			return err
		}
		if err := s.orgs.RemoveMember(txCtx, orgID, userID); err != nil {
			return err
		}
		return s.sessions.ClearActiveOrgForUser(txCtx, userID, orgID)
	})
	if err != nil {
		return "", err
	}
	s.log.Info("member removed", "org_id", orgID, "user_id", userID, "role", member.Role)
	return member.Role, nil
}

func (s *OrgService) RemoveMember(ctx context.Context, input RemoveMemberInput) error {
	if input.ActorID != input.UserID {
		if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleAdmin); err != nil {
			return err
		}
	}

	if _, err := s.removeMemberTx(ctx, input.OrgID, input.UserID); err != nil {
		return err
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventOrgMemberRemoved, input.ActorID, input.OrgID, &input.UserID))
	}

	return nil
}

type UpdateMemberRoleInput struct {
	OrgID   string
	UserID  string
	NewRole domain.OrgRole
	ActorID string // user performing the action
}

// updateMemberRoleTx does the actual work of changing userID's role within
// orgID — lookup, no-op-if-unchanged, owner-count upkeep, update, active-org
// sync — with no authorization check of its own, including no
// owner-escalation guard (see UpdateMemberRole's doc comment for why that
// guard stays out of this shared helper). Returns the member's prior role
// (empty if no change was made) for the caller to log/audit.
func (s *OrgService) updateMemberRoleTx(ctx context.Context, orgID, userID string, newRole domain.OrgRole) (domain.OrgRole, error) {
	member, err := s.orgs.GetMembership(ctx, orgID, userID)
	if err != nil {
		s.log.Error("failed to get membership for role update", "err", err, "org_id", orgID, "user_id", userID)
		return "", err
	}
	if member == nil {
		return "", domain.ErrOrgMemberNotFound
	}
	if member.Role == newRole {
		return "", nil
	}

	oldRole := member.Role
	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if member.Role == domain.OrgRoleOwner {
			if err := s.orgs.TryDecrementOrgOwnerCount(txCtx, orgID); err != nil {
				return err
			}
			if err := s.orgs.DecrementUserOrgOwnerCount(txCtx, userID); err != nil {
				return err
			}
		}

		if newRole == domain.OrgRoleOwner {
			if err := s.guardAndIncrementOwnerCount(txCtx, userID); err != nil {
				return err
			}
			if err := s.orgs.IncrementOrgOwnerCount(txCtx, orgID); err != nil {
				return err
			}
		}

		if err := s.orgs.UpdateMemberRole(txCtx, orgID, userID, newRole); err != nil {
			return err
		}

		return s.sessions.UpdateActiveOrgRoleForUser(txCtx, userID, orgID, newRole)
	})
	if err != nil {
		return "", err
	}
	s.log.Info("member role updated", "org_id", orgID, "user_id", userID, "old_role", oldRole, "new_role", newRole)
	return oldRole, nil
}

// UpdateMemberRole changes input.UserID's role within input.OrgID.
// Granting or revoking the Owner role is the highest-privilege action in an
// org and must itself be performed by an Owner — an Admin (who can
// otherwise manage Member/Admin transitions per RequireOrgRole at the HTTP
// layer) must not be able to self-escalate or hand Owner to someone else.
// This guard is deliberately kept out of updateMemberRoleTx — it protects
// against a same-org Admin abusing the self-service path, which doesn't
// apply to a platform admin acting via AdminUpdateMemberRole.
func (s *OrgService) UpdateMemberRole(ctx context.Context, input UpdateMemberRoleInput) error {
	if !input.NewRole.IsValid() {
		return domain.NewError("invalid_role", "Invalid organization role")
	}
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleAdmin); err != nil {
		return err
	}

	member, err := s.orgs.GetMembership(ctx, input.OrgID, input.UserID)
	if err != nil {
		s.log.Error("failed to get membership for role update", "err", err, "org_id", input.OrgID, "user_id", input.UserID)
		return err
	}
	if member == nil {
		return domain.ErrOrgMemberNotFound
	}
	if input.NewRole == domain.OrgRoleOwner || member.Role == domain.OrgRoleOwner {
		actor, err := s.orgs.GetMembership(ctx, input.OrgID, input.ActorID)
		if err != nil {
			s.log.Error("failed to get actor membership for role update", "err", err, "org_id", input.OrgID, "actor_id", input.ActorID)
			return err
		}
		if actor == nil || actor.Role != domain.OrgRoleOwner {
			return domain.ErrOrgForbidden
		}
	}

	oldRole, err := s.updateMemberRoleTx(ctx, input.OrgID, input.UserID, input.NewRole)
	if err != nil {
		return err
	}
	if oldRole == "" {
		return nil // no-op: already had this role
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventOrgMemberRoleChanged, input.ActorID, input.OrgID, &input.UserID))
	}

	return nil
}

type LeaveOrgInput struct {
	OrgID  string
	UserID string
}

func (s *OrgService) LeaveOrg(ctx context.Context, input LeaveOrgInput) error {
	return s.RemoveMember(ctx, RemoveMemberInput{OrgID: input.OrgID, UserID: input.UserID, ActorID: input.UserID})
}

type ListMembersInput struct {
	OrgID          string
	ActorID        string
	Role           *domain.OrgRole
	Search         *string
	OrderBy        string
	OrderDirection string
	Offset         int
	Limit          *int // nil = default 20; explicit 0 = unlimited; else capped at 100
}

type ListMembersResult struct {
	Members []domain.OrgMemberDetail `json:"members"`
	Limit   int                      `json:"limit"`
	Offset  int                      `json:"offset"`
}

func (s *OrgService) ListMembers(ctx context.Context, input ListMembersInput) (*ListMembersResult, error) {
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleMember); err != nil {
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
	return &ListMembersResult{Members: members, Limit: limit, Offset: input.Offset}, nil
}

type SetActiveOrgInput struct {
	SessionID string
	UserID    string
	OrgID     string
}

func (s *OrgService) SetActiveOrg(ctx context.Context, input SetActiveOrgInput) error {
	member, err := s.orgs.GetMembership(ctx, input.OrgID, input.UserID)
	if err != nil {
		return err
	}
	if member == nil {
		return domain.ErrOrgMemberNotFound
	}

	return s.sessions.SetActiveOrg(ctx, input.SessionID, input.OrgID, member.Role)
}

type ClearActiveOrgInput struct {
	SessionID string
}

func (s *OrgService) ClearActiveOrg(ctx context.Context, input ClearActiveOrgInput) error {
	return s.sessions.ClearActiveOrg(ctx, input.SessionID)
}

// ─── Platform-admin oversight ───────────────────────────────────
//
// Everything below is a platform-admin operation — gated by requireAdminRole
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

type AdminListOrgsInput struct {
	ActorID        string
	Search         *string
	CreatedAfter   *time.Time
	CreatedBefore  *time.Time
	OrderBy        string
	OrderDirection string
	Offset         int
	Limit          *int // nil = default 20; explicit 0 = unlimited; else capped at 100
}

type AdminListOrgsResult struct {
	Orgs   []domain.Organization `json:"orgs"`
	Limit  int                   `json:"limit"`
	Offset int                   `json:"offset"`
}

// AdminListOrgs lists every organization on the platform, filterable by
// name/slug search and creation-date range — the cross-org counterpart to
// ListUserOrgs, which is scoped to one user's memberships.
func (s *OrgService) AdminListOrgs(ctx context.Context, input AdminListOrgsInput) (*AdminListOrgsResult, error) {
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
	return &AdminListOrgsResult{Orgs: orgs, Limit: limit, Offset: input.Offset}, nil
}

// CountOrgs returns how many organizations match the input's filters
// (pagination ignored).
func (s *OrgService) CountOrgs(ctx context.Context, input AdminListOrgsInput) (int, error) {
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
func (s *OrgService) CountMembers(ctx context.Context, input ListMembersInput) (int, error) {
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleMember); err != nil {
		return 0, err
	}
	return s.orgs.CountMembers(ctx, input.OrgID, port.OrgMemberFilter{
		Role:   input.Role,
		Search: input.Search,
	})
}

// CountUserOrgs returns how many orgs the user belongs to that match search.
func (s *OrgService) CountUserOrgs(ctx context.Context, input ListUserOrgsInput) (int, error) {
	return s.orgs.CountUserOrgs(ctx, input.UserID, port.UserOrgFilter{Search: input.Search})
}

type AdminGetOrgInput struct {
	OrgID   string
	ActorID string
}

// AdminGetOrg fetches one organization regardless of the caller's membership
// in it. Publishes EventAdminOrgViewed: this exposes an org's metadata to
// platform staff who may not be members, and that access itself is worth an
// audit trail entry.
func (s *OrgService) AdminGetOrg(ctx context.Context, input AdminGetOrgInput) (*domain.Organization, error) {
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
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventAdminOrgViewed, input.ActorID, input.OrgID, nil))
	}

	return org, nil
}

type AdminListOrgMembersInput struct {
	OrgID          string
	ActorID        string
	Role           *domain.OrgRole
	Search         *string
	OrderBy        string
	OrderDirection string
	Offset         int
	Limit          *int // nil = default 20; explicit 0 = unlimited; else capped at 100
}

// AdminListOrgMembers lists orgID's members regardless of the caller's own
// membership in it — the admin-bypass counterpart to ListMembers, which
// requires the caller to already be a member. Publishes EventAdminOrgViewed
// for the same reason as AdminGetOrg: this is cross-tenant member data
// (emails, roles) being exposed to platform staff.
func (s *OrgService) AdminListOrgMembers(ctx context.Context, input AdminListOrgMembersInput) (*ListMembersResult, error) {
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
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventAdminOrgViewed, input.ActorID, input.OrgID, nil))
	}

	return &ListMembersResult{Members: members, Limit: limit, Offset: input.Offset}, nil
}

// AdminCountOrgMembers returns how many of orgID's members match the input's
// filters, bypassing the membership check (admin oversight). Pagination is
// ignored. Unlike AdminListOrgMembers it publishes no audit event — it
// exposes only a count, not member data.
func (s *OrgService) AdminCountOrgMembers(ctx context.Context, input AdminListOrgMembersInput) (int, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return 0, err
	}
	return s.orgs.CountMembers(ctx, input.OrgID, port.OrgMemberFilter{
		Role:   input.Role,
		Search: input.Search,
	})
}

type AdminOrgActionInput struct {
	OrgID   string
	ActorID string
}

// AdminDeleteOrg force-deletes orgID regardless of whether the caller is a
// member of it. Publishes EventAdminOrgDeleted — distinct from the
// self-service EventOrgDeleted — with the org's name/slug snapshotted into
// the event metadata, since the organizations row won't survive the delete
// for anything to join against later.
func (s *OrgService) AdminDeleteOrg(ctx context.Context, input AdminOrgActionInput) error {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return err
	}
	org, err := s.deleteOrgTx(ctx, input.OrgID)
	if err != nil {
		return err
	}

	if s.audit != nil {
		evt := audit.NewOrgEvent(audit.EventAdminOrgDeleted, input.ActorID, input.OrgID, nil)
		evt.Metadata = map[string]any{"orgName": org.Name, "orgSlug": org.Slug, "override": true}
		s.audit.Publish(ctx, evt)
	}

	return nil
}

type AdminAddMemberInput struct {
	OrgID   string
	UserID  string
	Role    domain.OrgRole
	ActorID string
}

// AdminAddMember force-adds userID to orgID with the given role, regardless
// of the caller's own membership. This is the recovery path for an org
// whose only owner left or was removed and is otherwise unmanageable by
// anyone — AdminRemoveMember/AdminUpdateMemberRole alone can't fix that,
// since both require the target to already be a member. Publishes
// EventAdminOrgMemberAdded.
func (s *OrgService) AdminAddMember(ctx context.Context, input AdminAddMemberInput) error {
	if !input.Role.IsValid() {
		return domain.NewError("invalid_role", "Invalid organization role")
	}
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return err
	}
	if err := s.addMemberTx(ctx, input.OrgID, input.UserID, input.Role); err != nil {
		return err
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventAdminOrgMemberAdded, input.ActorID, input.OrgID, &input.UserID))
	}

	return nil
}

type AdminRemoveMemberInput struct {
	OrgID   string
	UserID  string
	ActorID string
}

// AdminRemoveMember force-removes userID from orgID regardless of the
// caller's own membership. Publishes EventAdminOrgMemberRemoved — distinct
// from the self-service EventOrgMemberRemoved.
func (s *OrgService) AdminRemoveMember(ctx context.Context, input AdminRemoveMemberInput) error {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return err
	}
	if _, err := s.removeMemberTx(ctx, input.OrgID, input.UserID); err != nil {
		return err
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventAdminOrgMemberRemoved, input.ActorID, input.OrgID, &input.UserID))
	}

	return nil
}

type AdminUpdateMemberRoleInput struct {
	OrgID   string
	UserID  string
	NewRole domain.OrgRole
	ActorID string
}

// AdminUpdateMemberRole force-changes userID's role within orgID, including
// granting or revoking Owner — the self-service UpdateMemberRole's
// owner-escalation guard (only an Owner can touch the Owner role) is
// deliberately not applied here: that guard exists to stop a same-org Admin
// self-promoting, and doesn't apply to a platform admin acting from outside
// the org. Publishes EventAdminOrgMemberRoleChanged.
func (s *OrgService) AdminUpdateMemberRole(ctx context.Context, input AdminUpdateMemberRoleInput) error {
	if !input.NewRole.IsValid() {
		return domain.NewError("invalid_role", "Invalid organization role")
	}
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return err
	}
	oldRole, err := s.updateMemberRoleTx(ctx, input.OrgID, input.UserID, input.NewRole)
	if err != nil {
		return err
	}
	if oldRole == "" {
		return nil // no-op: already had this role
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventAdminOrgMemberRoleChanged, input.ActorID, input.OrgID, &input.UserID))
	}

	return nil
}
