package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type defaultTokenGen struct{}

func (g *defaultTokenGen) Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type OrgInviteService struct {
	orgInvites port.OrgInviteRepository
	orgs       port.OrgRepository
	users      port.UserRepository
	txManager  port.TxManager
	gen        port.TokenGenerator
	mailer     port.Mailer
	templates  port.TemplateProvider
	maxOrgs    int
	inviteTTL  time.Duration
	baseURL    string
	appName    string
	log        *slog.Logger
	audit      AuditPublisher
}

type OrgInviteServiceConfig struct {
	MaxOrgsPerUser  int
	InviteTTL       time.Duration
	BaseURL         string
	AppName         string
	TemplateProvider port.TemplateProvider
	URLValidator     *port.URLValidator
	Logger          *slog.Logger
	Audit           AuditPublisher
}

func NewOrgInviteService(
	orgInvites port.OrgInviteRepository,
	orgs port.OrgRepository,
	users port.UserRepository,
	txManager port.TxManager,
	gen port.TokenGenerator,
	mailer port.Mailer,
	cfg OrgInviteServiceConfig,
) *OrgInviteService {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if gen == nil {
		gen = &defaultTokenGen{}
	}
	if cfg.AppName == "" {
		cfg.AppName = "App"
	}
	resolvedMaxOrgs := resolveMaxOrgsPerUser(cfg.MaxOrgsPerUser)
	return &OrgInviteService{
		orgInvites: orgInvites,
		orgs:       orgs,
		users:      users,
		txManager:  txManager,
		gen:        gen,
		mailer:     mailer,
		templates:  resolveTemplates(cfg.TemplateProvider, cfg.URLValidator),
		maxOrgs:    resolvedMaxOrgs,
		inviteTTL:  cfg.InviteTTL,
		baseURL:    cfg.BaseURL,
		appName:    cfg.AppName,
		log:        cfg.Logger,
		audit:      cfg.Audit,
	}
}

// requireRole verifies actorID is a member of orgID with at least min role.
// See OrgService.requireRole for the rationale — the same defense-in-depth
// applies here: HTTP middleware pre-checks this, this is the real authority.
func (s *OrgInviteService) requireRole(ctx context.Context, orgID, actorID string, min domain.OrgRole) error {
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

// ─── Input types ────────────────────────────────────────────────────

type CreateOrgInviteInput struct {
	OrgID     string
	Email     string
	Role      domain.OrgRole
	InvitedBy string
}

type AcceptInviteInput struct {
	UserID  string
	RawCode string
}

// ─── CreateOrgInvite ────────────────────────────────────────────────

func (s *OrgInviteService) CreateOrgInvite(ctx context.Context, input CreateOrgInviteInput) (*domain.OrgInvite, error) {
	if !input.Role.IsValid() {
		return nil, domain.NewError("invalid_role", "Invalid organization role", 400)
	}

	if s.inviteTTL <= 0 {
		return nil, domain.NewError("internal_error", "Organization invites are not configured", 500)
	}

	actor, err := s.orgs.GetMembership(ctx, input.OrgID, input.InvitedBy)
	if err != nil {
		s.log.Error("failed to get actor membership for org invite", "err", err, "org_id", input.OrgID, "invited_by", input.InvitedBy)
		return nil, err
	}
	if actor == nil || actor.Role.Weight() < domain.OrgRoleAdmin.Weight() {
		return nil, domain.ErrOrgForbidden
	}

	// Inviting someone directly as Owner grants the org's highest privilege
	// level; only an existing Owner may do that. Admins (allowed to create
	// Member/Admin invites by the check above) must not be able to hand out
	// ownership.
	if input.Role == domain.OrgRoleOwner && actor.Role != domain.OrgRoleOwner {
		return nil, domain.ErrOrgForbidden
	}

	if s.mailer == nil {
		return nil, domain.NewError("email_not_configured", "Email sender is not configured", 500)
	}

	raw, err := s.gen.Generate()
	if err != nil {
		s.log.Error("failed to generate org invite code", "err", err)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	now := time.Now().UTC()
	invite := &domain.OrgInvite{
		ID:        generateID(),
		OrgID:     input.OrgID,
		Email:     strings.ToLower(strings.TrimSpace(input.Email)),
		Role:      input.Role,
		CodeHash:  hashToken(raw),
		RawCode:   raw,
		InvitedBy: input.InvitedBy,
		ExpiresAt: now.Add(s.inviteTTL),
		CreatedAt: now,
	}

	if err := s.orgInvites.Create(ctx, invite); err != nil {
		s.log.Error("failed to create org invite", "err", err, "org_id", input.OrgID, "email", input.Email)
		return nil, err
	}

	if err := s.sendOrgInviteEmail(ctx, invite); err != nil {
		s.log.Error("failed to send org invite email", "err", err, "invite_id", invite.ID, "email", input.Email)
		return nil, domain.NewError("email_failed", "Failed to send invite email", 500)
	}

	s.log.Info("org invite created", "org_id", input.OrgID, "email", input.Email, "role", input.Role, "invited_by", input.InvitedBy)
	return invite, nil
}

// ─── AcceptInvite ───────────────────────────────────────────────────

func (s *OrgInviteService) AcceptInvite(ctx context.Context, input AcceptInviteInput) error {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrForbidden
	}

	codeHash := hashToken(input.RawCode)
	invite, err := s.orgInvites.GetByCodeHash(ctx, codeHash)
	if err != nil || invite == nil {
		return domain.ErrOrgInviteExpired
	}

	if !strings.EqualFold(user.Email, invite.Email) {
		return domain.ErrOrgInviteEmailMismatch
	}

	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		claimed, err := s.orgInvites.ClaimInvite(txCtx, invite.ID)
		if err != nil {
			return err
		}
		if !claimed {
			return domain.ErrOrgInviteExpired
		}

		if invite.Role == domain.OrgRoleOwner {
			if err := s.orgs.IncrementUserOrgOwnerCount(txCtx, input.UserID, s.maxOrgs); err != nil {
				return err
			}
			if err := s.orgs.IncrementOrgOwnerCount(txCtx, invite.OrgID); err != nil {
				return err
			}
		}

		if err := s.orgs.IncrementOrgMemberCount(txCtx, invite.OrgID, 10000); err != nil {
			return err
		}

		return s.orgs.AddMember(txCtx, &domain.OrgMember{
			OrgID:    invite.OrgID,
			UserID:   input.UserID,
			Role:     invite.Role,
			JoinedAt: time.Now().UTC(),
		})
	})
	if err != nil {
		return err
	}
	s.log.Info("org invite accepted", "org_id", invite.OrgID, "user_id", input.UserID, "email", user.Email)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewOrgEvent(audit.EventOrgMemberInvited, input.UserID, invite.OrgID, &input.UserID))
	}

	return nil
}

// ─── ListOrgInvites ─────────────────────────────────────────────────

func (s *OrgInviteService) ListOrgInvites(ctx context.Context, orgID, actorID string) ([]domain.OrgInvite, error) {
	if err := s.requireRole(ctx, orgID, actorID, domain.OrgRoleAdmin); err != nil {
		return nil, err
	}
	return s.orgInvites.ListByOrgID(ctx, orgID)
}

// ─── DeleteOrgInvite ────────────────────────────────────────────────

// DeleteOrgInvite deletes inviteID, which must belong to orgID — this also
// guards against an admin of one org deleting an invite that actually
// belongs to a different org by guessing/enumerating its ID.
func (s *OrgInviteService) DeleteOrgInvite(ctx context.Context, orgID, inviteID, actorID string) error {
	if err := s.requireRole(ctx, orgID, actorID, domain.OrgRoleAdmin); err != nil {
		return err
	}
	invite, err := s.orgInvites.GetByID(ctx, inviteID)
	if err != nil {
		s.log.Error("failed to get org invite for deletion", "err", err, "invite_id", inviteID)
		return err
	}
	if invite == nil || invite.OrgID != orgID {
		return domain.NewError("invite_not_found", "Invite not found", 404)
	}
	if err := s.orgInvites.Delete(ctx, inviteID); err != nil {
		s.log.Error("failed to delete org invite", "err", err, "invite_id", inviteID)
		return err
	}
	s.log.Info("org invite deleted", "invite_id", inviteID)
	return nil
}

// ─── ResendOrgInviteEmail ───────────────────────────────────────────

// ResendOrgInviteEmail resends inviteID, which must belong to orgID — same
// cross-org guard as DeleteOrgInvite.
func (s *OrgInviteService) ResendOrgInviteEmail(ctx context.Context, orgID, inviteID, actorID string) error {
	if err := s.requireRole(ctx, orgID, actorID, domain.OrgRoleAdmin); err != nil {
		return err
	}
	invite, err := s.orgInvites.GetByID(ctx, inviteID)
	if err != nil {
		s.log.Error("failed to get org invite for resend", "err", err, "invite_id", inviteID)
		return err
	}
	if invite == nil || invite.OrgID != orgID {
		return domain.NewError("invite_not_found", "Invite not found", 404)
	}

	if s.mailer == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured", 500)
	}

	raw, err := s.gen.Generate()
	if err != nil {
		s.log.Error("failed to generate org invite code", "err", err, "invite_id", inviteID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	invite.CodeHash = hashToken(raw)
	invite.RawCode = raw
	invite.ExpiresAt = time.Now().UTC().Add(s.inviteTTL)

	if err := s.orgInvites.Update(ctx, invite); err != nil {
		s.log.Error("failed to update org invite for resend", "err", err, "invite_id", inviteID)
		return err
	}

	if err := s.sendOrgInviteEmail(ctx, invite); err != nil {
		s.log.Error("failed to resend org invite email", "err", err, "invite_id", inviteID)
		return domain.NewError("email_failed", "Failed to send invite email", 500)
	}

	s.log.Info("org invite resent", "invite_id", inviteID, "email", invite.Email)
	return nil
}

// ─── sendOrgInviteEmail ─────────────────────────────────────────────

func (s *OrgInviteService) sendOrgInviteEmail(ctx context.Context, invite *domain.OrgInvite) error {
	if s.mailer == nil {
		return nil
	}
	url := s.baseURL + "/invite?token=" + invite.RawCode
	org, _ := s.orgs.GetByID(ctx, invite.OrgID)
	orgName := "an organization"
	if org != nil {
		orgName = org.Name
	}
	result, err := s.templates.Render(port.OrgInviteData{
		AppName:   s.appName,
		OrgName:   orgName,
		InviteURL: url,
		ExpiresIn: s.inviteTTL,
	})
	if err != nil {
		return fmt.Errorf("render org invite template: %w", err)
	}
	return s.mailer.Send(ctx, invite.Email, result.Subject, result.HTML, result.Text)
}
