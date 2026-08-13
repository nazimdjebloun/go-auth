package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type OrgService struct {
	orgs      port.OrgRepository
	users     port.UserRepository
	sessions  port.SessionRepository
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
	sessions port.SessionRepository,
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
		return nil, domain.NewError("invalid_slug", "Slug must be 255 characters or less", 400)
	}
	if input.Name == "" {
		return nil, domain.NewError("invalid_name", "Organization name is required", 400)
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

func (s *OrgService) DeleteOrg(ctx context.Context, input DeleteOrgInput) error {
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleOwner); err != nil {
		return err
	}
	org, err := s.orgs.GetByID(ctx, input.OrgID)
	if err != nil {
		s.log.Error("failed to get org for deletion", "err", err, "org_id", input.OrgID)
		return err
	}
	if org == nil {
		return domain.ErrOrgNotFound
	}

	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := s.orgs.DecrementOwnerCountForOrgOwners(txCtx, input.OrgID); err != nil {
			return err
		}
		if err := s.sessions.ClearActiveOrgForAllMembers(txCtx, input.OrgID); err != nil {
			return err
		}
		return s.orgs.Delete(txCtx, input.OrgID)
	})
	if err != nil {
		s.log.Error("failed to delete org", "err", err, "org_id", input.OrgID)
		return err
	}
	s.log.Info("org deleted", "org_id", input.OrgID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventOrgDeleted, "", input.OrgID, nil))
	}

	return nil
}

func (s *OrgService) ListUserOrgs(ctx context.Context, userID string) ([]domain.Organization, error) {
	return s.orgs.ListUserOrgs(ctx, userID)
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
func (s *OrgService) AddMember(ctx context.Context, input AddMemberInput) error {
	if !input.Role.IsValid() {
		return domain.NewError("invalid_role", "Invalid organization role", 400)
	}
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleAdmin); err != nil {
		return err
	}

	membership, err := s.orgs.GetMembership(ctx, input.OrgID, input.UserID)
	if err != nil {
		s.log.Error("failed to check membership", "err", err, "org_id", input.OrgID, "user_id", input.UserID)
		return err
	}
	if membership != nil {
		return domain.ErrOrgMemberExists
	}

	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if input.Role == domain.OrgRoleOwner {
			if err := s.guardAndIncrementOwnerCount(txCtx, input.UserID); err != nil {
				return err
			}
			if err := s.orgs.IncrementOrgOwnerCount(txCtx, input.OrgID); err != nil {
				return err
			}
		}

		if err := s.orgs.IncrementOrgMemberCount(txCtx, input.OrgID, 10000); err != nil {
			return err
		}

		return s.orgs.AddMember(txCtx, &domain.OrgMember{
			OrgID:    input.OrgID,
			UserID:   input.UserID,
			Role:     input.Role,
			JoinedAt: time.Now().UTC(),
		})
	})
	if err != nil {
		return err
	}
	s.log.Info("member added", "org_id", input.OrgID, "user_id", input.UserID, "role", input.Role)
	return nil
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
func (s *OrgService) RemoveMember(ctx context.Context, input RemoveMemberInput) error {
	if input.ActorID != input.UserID {
		if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleAdmin); err != nil {
			return err
		}
	}

	member, err := s.orgs.GetMembership(ctx, input.OrgID, input.UserID)
	if err != nil {
		s.log.Error("failed to get membership for removal", "err", err, "org_id", input.OrgID, "user_id", input.UserID)
		return err
	}
	if member == nil {
		return domain.ErrOrgMemberNotFound
	}

	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if member.Role == domain.OrgRoleOwner {
			if err := s.orgs.TryDecrementOrgOwnerCount(txCtx, input.OrgID); err != nil {
				return err
			}
			if err := s.orgs.DecrementUserOrgOwnerCount(txCtx, input.UserID); err != nil {
				return err
			}
		}

		if err := s.orgs.DecrementOrgMemberCount(txCtx, input.OrgID); err != nil {
			return err
		}
		if err := s.orgs.RemoveMember(txCtx, input.OrgID, input.UserID); err != nil {
			return err
		}
		return s.sessions.ClearActiveOrgForUser(txCtx, input.UserID, input.OrgID)
	})
	if err != nil {
		return err
	}
	s.log.Info("member removed", "org_id", input.OrgID, "user_id", input.UserID, "role", member.Role)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventOrgMemberRemoved, "", input.OrgID, &input.UserID))
	}

	return nil
}

type UpdateMemberRoleInput struct {
	OrgID   string
	UserID  string
	NewRole domain.OrgRole
	ActorID string // user performing the action
}

func (s *OrgService) UpdateMemberRole(ctx context.Context, input UpdateMemberRoleInput) error {
	if !input.NewRole.IsValid() {
		return domain.NewError("invalid_role", "Invalid organization role", 400)
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

	if member.Role == input.NewRole {
		return nil
	}

	// Granting or revoking the Owner role is the highest-privilege action in
	// an org and must itself be performed by an Owner — an Admin (who can
	// otherwise manage Member/Admin transitions per RequireOrgRole at the
	// HTTP layer) must not be able to self-escalate or hand Owner to someone
	// else.
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

	oldRole := member.Role
	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if member.Role == domain.OrgRoleOwner {
			if err := s.orgs.TryDecrementOrgOwnerCount(txCtx, input.OrgID); err != nil {
				return err
			}
			if err := s.orgs.DecrementUserOrgOwnerCount(txCtx, input.UserID); err != nil {
				return err
			}
		}

		if input.NewRole == domain.OrgRoleOwner {
			if err := s.guardAndIncrementOwnerCount(txCtx, input.UserID); err != nil {
				return err
			}
			if err := s.orgs.IncrementOrgOwnerCount(txCtx, input.OrgID); err != nil {
				return err
			}
		}

		if err := s.orgs.UpdateMemberRole(txCtx, input.OrgID, input.UserID, input.NewRole); err != nil {
			return err
		}

		return s.sessions.UpdateActiveOrgRoleForUser(txCtx, input.UserID, input.OrgID, input.NewRole)
	})
	if err != nil {
		return err
	}
	s.log.Info("member role updated", "org_id", input.OrgID, "user_id", input.UserID, "old_role", oldRole, "new_role", input.NewRole)
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
	OrgID   string
	ActorID string
	Offset  int
	Limit   int
}

func (s *OrgService) ListMembers(ctx context.Context, input ListMembersInput) ([]domain.OrgMemberDetail, int, error) {
	if err := s.requireRole(ctx, input.OrgID, input.ActorID, domain.OrgRoleMember); err != nil {
		return nil, 0, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}
	return s.orgs.ListMembers(ctx, input.OrgID, input.Offset, limit)
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
