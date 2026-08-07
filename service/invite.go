package service

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type InviteService struct {
	users      port.UserRepository
	sessions   port.SessionRepository
	invites    port.InviteRepository
	hasher     port.Hasher
	gen        port.TokenGenerator
	mailer     port.Mailer
	templates  port.TemplateProvider
	config     Config
	sessionSvc *SessionService
	log        *slog.Logger
	audit      AuditPublisher
}

func NewInviteService(
	users port.UserRepository,
	sessions port.SessionRepository,
	invites port.InviteRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	mailer port.Mailer,
	config Config,
	sessionSvc *SessionService,
) *InviteService {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &InviteService{
		users:      users,
		sessions:   sessions,
		invites:    invites,
		hasher:     hasher,
		gen:        gen,
		mailer:     mailer,
		templates:  resolveTemplates(config.TemplateProvider, config.URLValidator),
		config:     config,
		sessionSvc: sessionSvc,
		log:        config.Logger,
		audit:      config.Audit,
	}
}

func (s *InviteService) GetInviteByToken(ctx context.Context, rawToken string) (*domain.Invite, *domain.AuthError) {
	invite, err := s.invites.GetByCode(ctx, hashToken(rawToken))
	if err != nil || invite == nil {
		return nil, domain.ErrInviteNotFound
	}

	if invite.Status != domain.InvitePending {
		if invite.Status == domain.InviteAccepted {
			return nil, domain.ErrInviteAlreadyUsed
		}
		if invite.Status == domain.InviteRevoked {
			return nil, domain.ErrInviteRevoked
		}
		return nil, domain.ErrInviteNotFound
	}

	if time.Now().UTC().After(invite.ExpiresAt) {
		invite.Status = domain.InviteExpired
		s.invites.Update(ctx, invite)
		return nil, domain.ErrInviteExpired
	}

	return invite, nil
}

func (s *InviteService) CreateInvite(ctx context.Context, input CreateInviteInput) (*domain.Invite, *domain.AuthError) {
	if !s.config.EnableInvite {
		return nil, domain.ErrMethodDisabled
	}
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}

	raw, err := s.gen.Generate()
	if err != nil {
		s.log.Error("failed to generate invite code", "err", err, "email", input.Email)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	now := time.Now().UTC()
	invite := &domain.Invite{
		ID:        generateID(),
		Email:     input.Email,
		Code:      hashToken(raw),
		RawCode:   raw,
		Status:    domain.InvitePending,
		CreatedBy: input.AdminID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.config.InviteTTL),
	}

	if err := s.invites.Create(ctx, invite); err != nil {
		s.log.Error("failed to create invite", "err", err, "email", input.Email)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("invite created", "invite_id", invite.ID, "email", input.Email, "admin_id", input.AdminID)
	return invite, nil
}

func (s *InviteService) CompleteInviteRegistration(ctx context.Context, input CompleteInviteInput) (*CompleteInviteResult, *domain.AuthError) {
	if !s.config.EnableInvite {
		return nil, domain.ErrMethodDisabled
	}
	invite, err := s.invites.GetByCode(ctx, hashToken(input.Code))
	if err != nil || invite == nil {
		return nil, domain.ErrInviteNotFound
	}

	if invite.Status != domain.InvitePending {
		return nil, domain.ErrInviteAlreadyUsed
	}

	if time.Now().UTC().After(invite.ExpiresAt) {
		return nil, domain.ErrInviteExpired
	}

	if strings.TrimSpace(input.Name) == "" {
		return nil, domain.NewError("name_required", "Name is required", 400)
	}
	input.Name = strings.TrimSpace(input.Name)

	if input.Password != input.ConfirmPassword {
		return nil, domain.NewError("password_mismatch", "Passwords do not match", 400)
	}

	if err := s.config.PasswordPolicy.Validate(input.Password); err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		s.log.Error("failed to hash password", "err", err, "invite_id", invite.ID)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:           generateID(),
		Email:        invite.Email,
		PasswordHash: &hash,
		Name:         input.Name,
		Role:         domain.RoleUser,
		IsVerified:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		s.log.Error("failed to create user from invite", "err", err, "email", invite.Email)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	invite.Status = domain.InviteAccepted
	now2 := time.Now().UTC()
	invite.AcceptedAt = &now2
	s.invites.Update(ctx, invite)

	session, rawToken, refreshToken, err := s.sessionSvc.Create(ctx, user.ID, input.IP, input.UserAgent)
	if err != nil {
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("invite registered", "user_id", user.ID, "email", user.Email, "invite_id", invite.ID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewUserRegisteredEvent(user.ID, nil, ""))
	}

	return &CompleteInviteResult{
		User:         user,
		Session:      session,
		SessionToken: rawToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *InviteService) ListInvites(ctx context.Context, input ListInvitesInput) ([]domain.Invite, int, *domain.AuthError) {
	var search *string
	if input.Search != "" {
		search = &input.Search
	}
	var status *string
	if input.Status != "" {
		status = &input.Status
	}

	invites, total, err := s.invites.List(ctx, port.InviteFilter{
		Offset: input.Offset,
		Limit:  input.Limit,
		Search: search,
		Status: status,
	})
	if err != nil {
		s.log.Error("failed to list invites", "err", err)
		return nil, 0, domain.NewError("internal_error", "Internal server error", 500)
	}
	return invites, total, nil
}

func (s *InviteService) HardDeleteInvite(ctx context.Context, inviteID string) *domain.AuthError {
	if err := s.invites.Delete(ctx, inviteID); err != nil {
		s.log.Error("failed to delete invite", "err", err, "invite_id", inviteID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}
	s.log.Info("invite deleted", "invite_id", inviteID)
	return nil
}

func (s *InviteService) RevokeInvite(ctx context.Context, inviteID string) *domain.AuthError {
	invite, err := s.invites.GetByID(ctx, inviteID)
	if err != nil || invite == nil {
		return domain.ErrInviteNotFound
	}

	invite.Status = domain.InviteRevoked
	if err := s.invites.Update(ctx, invite); err != nil {
		s.log.Error("failed to revoke invite", "err", err, "invite_id", inviteID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}
	s.log.Info("invite revoked", "invite_id", inviteID)
	return nil
}

func (s *InviteService) ResendInviteEmail(ctx context.Context, inviteID string) *domain.AuthError {
	invite, err := s.invites.GetByID(ctx, inviteID)
	if err != nil || invite == nil {
		return domain.ErrInviteNotFound
	}

	raw, err := s.gen.Generate()
	if err != nil {
		s.log.Error("failed to generate invite code", "err", err, "invite_id", inviteID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	invite.Code = hashToken(raw)
	invite.ExpiresAt = time.Now().UTC().Add(s.config.InviteTTL)

	if err := s.invites.Update(ctx, invite); err != nil {
		s.log.Error("failed to update invite", "err", err, "invite_id", inviteID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	if s.mailer != nil {
		url := s.config.BaseURL + "/invite?token=" + raw
		result, tplErr := s.templates.Render(port.InviteData{
			AppName:   s.config.AppName,
			InviteURL: url,
			ExpiresIn: s.config.InviteTTL,
		})
		if tplErr != nil {
			s.log.Error("failed to render invite email template", "err", tplErr, "invite_id", inviteID)
			return domain.NewError("internal_error", "Internal server error", 500)
		}
		if err := s.mailer.Send(ctx, invite.Email, result.Subject, result.HTML, result.Text); err != nil {
			s.log.Error("failed to send invite email", "err", err, "invite_id", inviteID)
			return domain.NewError("email_failed", "Failed to send invite email", 500)
		}
	}

	s.log.Info("invite resent", "invite_id", inviteID, "email", invite.Email)
	return nil
}
