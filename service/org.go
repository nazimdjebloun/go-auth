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

func (s *OrgService) GetByID(ctx context.Context, orgID string) (*domain.Organization, error) {
	org, err := s.orgs.GetByID(ctx, orgID)
	if err != nil {
		s.log.Error("failed to get org by id", "err", err, "org_id", orgID)
		return nil, err
	}
	if org == nil {
		return nil, domain.ErrOrgNotFound
	}
	return org, nil
}

func (s *OrgService) GetBySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	org, err := s.orgs.GetBySlug(ctx, slug)
	if err != nil {
		s.log.Error("failed to get org by slug", "err", err, "slug", slug)
		return nil, err
	}
	if org == nil {
		return nil, domain.ErrOrgNotFound
	}
	return org, nil
}

type UpdateOrgInput struct {
	OrgID string
	Name  *string
	Slug  *string
}

func (s *OrgService) UpdateOrg(ctx context.Context, input UpdateOrgInput) (*domain.Organization, error) {
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

func (s *OrgService) DeleteOrg(ctx context.Context, orgID string) error {
	org, err := s.orgs.GetByID(ctx, orgID)
	if err != nil {
		s.log.Error("failed to get org for deletion", "err", err, "org_id", orgID)
		return err
	}
	if org == nil {
		return domain.ErrOrgNotFound
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
		return err
	}
	s.log.Info("org deleted", "org_id", orgID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventOrgDeleted, "", orgID, nil))
	}

	return nil
}

func (s *OrgService) ListUserOrgs(ctx context.Context, userID string) ([]domain.Organization, error) {
	return s.orgs.ListUserOrgs(ctx, userID)
}

func (s *OrgService) GetMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error) {
	m, err := s.orgs.GetMembership(ctx, orgID, userID)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, domain.ErrOrgMemberNotFound
	}
	return m, nil
}

type AddMemberInput struct {
	OrgID  string
	UserID string
	Role   domain.OrgRole
}

func (s *OrgService) AddMember(ctx context.Context, input AddMemberInput) error {
	if !input.Role.IsValid() {
		return domain.NewError("invalid_role", "Invalid organization role", 400)
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

func (s *OrgService) RemoveMember(ctx context.Context, orgID, userID string) error {
	member, err := s.orgs.GetMembership(ctx, orgID, userID)
	if err != nil {
		s.log.Error("failed to get membership for removal", "err", err, "org_id", orgID, "user_id", userID)
		return err
	}
	if member == nil {
		return domain.ErrOrgMemberNotFound
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
		return err
	}
	s.log.Info("member removed", "org_id", orgID, "user_id", userID, "role", member.Role)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventOrgMemberRemoved, "", orgID, &userID))
	}

	return nil
}

type UpdateMemberRoleInput struct {
	OrgID    string
	UserID   string
	NewRole  domain.OrgRole
	ActorID  string // user performing the action
}

func (s *OrgService) UpdateMemberRole(ctx context.Context, input UpdateMemberRoleInput) error {
	if !input.NewRole.IsValid() {
		return domain.NewError("invalid_role", "Invalid organization role", 400)
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

func (s *OrgService) LeaveOrg(ctx context.Context, orgID, userID string) error {
	return s.RemoveMember(ctx, orgID, userID)
}

func (s *OrgService) ListMembers(ctx context.Context, orgID string, offset, limit int) ([]domain.OrgMemberDetail, int, error) {
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}
	return s.orgs.ListMembers(ctx, orgID, offset, limit)
}

func (s *OrgService) SetActiveOrg(ctx context.Context, sessionID, userID, orgID string) error {
	member, err := s.orgs.GetMembership(ctx, orgID, userID)
	if err != nil {
		return err
	}
	if member == nil {
		return domain.ErrOrgMemberNotFound
	}

	return s.sessions.SetActiveOrg(ctx, sessionID, orgID, member.Role)
}

func (s *OrgService) ClearActiveOrg(ctx context.Context, sessionID, orgID string) error {
	return s.sessions.ClearActiveOrgForUser(ctx, sessionID, orgID)
}
