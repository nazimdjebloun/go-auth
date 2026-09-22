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

		// Inside the transaction: the record commits with the org and its
		// owner membership.
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewOrgEvent(audit.EventOrgCreated, input.OwnerID, org.ID, nil)); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	s.log.Info("org created", "org_id", org.ID, "slug", org.Slug, "owner_id", input.OwnerID)
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
func (s *OrgService) deleteOrgTx(ctx context.Context, orgID string, record func(txCtx context.Context, org *domain.Organization) error) (*domain.Organization, error) {
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
		// The delete is the arbiter, like the membership writes in
		// removeMemberTx/updateMemberRoleTx: a concurrent delete that
		// already removed the row matches zero rows here, and this
		// transaction rolls back its owner-count upkeep instead of
		// applying it a second time.
		deleted, err := s.orgs.Delete(txCtx, orgID)
		if err != nil {
			return err
		}
		if !deleted {
			return domain.ErrOrgNotFound
		}
		// Inside the transaction: the record commits with the deletion it
		// describes, so a crash cannot leave an org gone with no record.
		if record != nil {
			if err := record(txCtx, org); err != nil {
				return err
			}
		}
		return nil
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
	_, err := s.deleteOrgTx(ctx, input.OrgID, func(txCtx context.Context, org *domain.Organization) error {
		if s.audit == nil {
			return nil
		}
		evt := audit.NewOrgEvent(audit.EventOrgDeleted, input.ActorID, input.OrgID, nil)
		evt.Metadata = map[string]any{"orgName": org.Name, "orgSlug": org.Slug}
		return s.audit.Record(txCtx, evt)
	})
	return err
}

type ListUserOrgsInput struct {
	UserID         string
	Search         *string
	Role           *domain.OrgRole
	OrderBy        port.UserOrgSortField
	OrderDirection port.SortDirection
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
func (s *OrgService) addMemberTx(ctx context.Context, orgID, userID string, role domain.OrgRole, record func(txCtx context.Context) error) error {
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

		if err := s.orgs.AddMember(txCtx, &domain.OrgMember{
			OrgID:    orgID,
			UserID:   userID,
			Role:     role,
			JoinedAt: time.Now().UTC(),
		}); err != nil {
			// Lost a same-member add race after the existence check above:
			// the unique constraint is the backstop, and the loser's
			// counter upkeep rolls back with it.
			if errors.Is(err, port.ErrDuplicateKey) {
				return domain.ErrOrgMemberExists
			}
			return err
		}
		// Inside the transaction: the record commits with the membership.
		if record != nil {
			if err := record(txCtx); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.log.Info("member added", "org_id", orgID, "user_id", userID, "role", role)
	return nil
}

func (s *OrgService) AddMember(ctx context.Context, input AddMemberInput) error {
	if !input.Role.IsValid() {
		return domain.ErrInvalidOrgRole
	}
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleAdmin); err != nil {
		return err
	}
	return s.addMemberTx(ctx, input.OrgID, input.UserID, input.Role, func(txCtx context.Context) error {
		if s.audit == nil {
			return nil
		}
		return s.audit.Record(txCtx, audit.NewOrgEvent(audit.EventOrgMemberInvited, input.ActorID, input.OrgID, &input.UserID))
	})
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
func (s *OrgService) removeMemberTx(ctx context.Context, orgID, userID string, record func(txCtx context.Context, removedRole domain.OrgRole) error) (domain.OrgRole, error) {
	var removedRole domain.OrgRole
	err := s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		// The membership is read inside the transaction and the delete
		// below is conditional on the role read here — it runs FIRST, so
		// only the request that actually removes the row proceeds to the
		// counter upkeep. A concurrent removal or role change between this
		// read and the delete matches zero rows, and the transaction
		// aborts before any counter moves.
		member, err := s.orgs.GetMembership(txCtx, orgID, userID)
		if err != nil {
			s.log.Error("failed to get membership for removal", "err", err, "org_id", orgID, "user_id", userID)
			return err
		}
		if member == nil {
			return domain.ErrOrgMemberNotFound
		}

		// Snapshot the role before the conditional write below (see
		// updateMemberRoleTx): it is the role the delete asserts and the
		// counters are keyed to.
		removedRole = member.Role
		removed, err := s.orgs.RemoveMember(txCtx, orgID, userID, member.Role)
		if err != nil {
			return err
		}
		if !removed {
			return s.membershipRaceError(txCtx, orgID, userID, removedRole)
		}

		if removedRole == domain.OrgRoleOwner {
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
		if err := s.sessions.ClearActiveOrgForUser(txCtx, userID, orgID); err != nil {
			return err
		}
		// Inside the transaction: the record commits with the removal.
		if record != nil {
			if err := record(txCtx, removedRole); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	s.log.Info("member removed", "org_id", orgID, "user_id", userID, "role", removedRole)
	return removedRole, nil
}

// membershipRaceError disambiguates a guarded membership write that matched
// zero rows: the membership either vanished concurrently (not found) or its
// role changed under the caller (conflict — refetching and retrying with the
// fresh role is safe, because the caller's transaction rolled back).
func (s *OrgService) membershipRaceError(txCtx context.Context, orgID, userID string, expectRole domain.OrgRole) error {
	current, err := s.orgs.GetMembership(txCtx, orgID, userID)
	if err != nil {
		return err
	}
	if current == nil {
		return domain.ErrOrgMemberNotFound
	}
	if current.Role != expectRole {
		return domain.ErrOrgMemberConflict
	}
	// Same role but the write still matched nothing: treat it as a lost race.
	return domain.ErrOrgMemberConflict
}

func (s *OrgService) RemoveMember(ctx context.Context, input RemoveMemberInput) error {
	if input.ActorID != input.UserID {
		if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleAdmin); err != nil {
			return err
		}
	}

	_, err := s.removeMemberTx(ctx, input.OrgID, input.UserID, func(txCtx context.Context, _ domain.OrgRole) error {
		if s.audit == nil {
			return nil
		}
		return s.audit.Record(txCtx, audit.NewOrgEvent(audit.EventOrgMemberRemoved, input.ActorID, input.OrgID, &input.UserID))
	})
	return err
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
func (s *OrgService) updateMemberRoleTx(ctx context.Context, orgID, userID string, newRole domain.OrgRole, record func(txCtx context.Context, oldRole domain.OrgRole) error) (domain.OrgRole, error) {
	var oldRole domain.OrgRole
	err := s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		// Like removeMemberTx, the membership is read inside the
		// transaction and the role update below is conditional on that
		// role — and it runs FIRST, so only the request that actually
		// changes the row proceeds to the counter upkeep.
		member, err := s.orgs.GetMembership(txCtx, orgID, userID)
		if err != nil {
			s.log.Error("failed to get membership for role update", "err", err, "org_id", orgID, "user_id", userID)
			return err
		}
		if member == nil {
			return domain.ErrOrgMemberNotFound
		}
		if member.Role == newRole {
			return nil
		}

		// Snapshot the pre-change role before the conditional write below:
		// repository implementations may hand out (and then mutate) the
		// stored struct rather than a copy, so member.Role must not be
		// re-read after this point.
		oldRole = member.Role

		updated, err := s.orgs.UpdateMemberRole(txCtx, orgID, userID, oldRole, newRole)
		if err != nil {
			return err
		}
		if !updated {
			// A concurrent request changed the same membership after this
			// transaction's read: if it landed exactly the requested role
			// this is an idempotent no-op, otherwise the caller must retry
			// against the fresh state.
			current, err := s.orgs.GetMembership(txCtx, orgID, userID)
			if err != nil {
				return err
			}
			if current == nil {
				return domain.ErrOrgMemberNotFound
			}
			if current.Role == newRole {
				oldRole = ""
				return nil
			}
			return domain.ErrOrgMemberConflict
		}

		if oldRole == domain.OrgRoleOwner {
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

		if err := s.sessions.UpdateActiveOrgRoleForUser(txCtx, userID, orgID, newRole); err != nil {
			return err
		}
		// Inside the transaction: the record commits with the role change.
		// A no-op update (oldRole == "") records nothing here — the caller
		// treats it as "no change", so the closure is only invoked when a
		// role actually moved.
		if record != nil && oldRole != "" {
			if err := record(txCtx, oldRole); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if oldRole != "" {
		s.log.Info("member role updated", "org_id", orgID, "user_id", userID, "old_role", oldRole, "new_role", newRole)
	}
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
		return domain.ErrInvalidOrgRole
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

	oldRole, err := s.updateMemberRoleTx(ctx, input.OrgID, input.UserID, input.NewRole, func(txCtx context.Context, _ domain.OrgRole) error {
		if s.audit == nil {
			return nil
		}
		return s.audit.Record(txCtx, audit.NewOrgEvent(audit.EventOrgMemberRoleChanged, input.ActorID, input.OrgID, &input.UserID))
	})
	if err != nil {
		return err
	}
	if oldRole == "" {
		return nil // no-op: already had this role
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
	OrderBy        port.OrgMemberSortField
	OrderDirection port.SortDirection
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
