package service

import (
	"context"
	"strings"
	"time"

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
	config     Config
	sessionSvc *SessionService
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
	return &InviteService{
		users:      users,
		sessions:   sessions,
		invites:    invites,
		hasher:     hasher,
		gen:        gen,
		mailer:     mailer,
		config:     config,
		sessionSvc: sessionSvc,
	}
}

func (s *InviteService) CreateInvite(ctx context.Context, input CreateInviteInput) (*domain.Invite, *domain.AuthError) {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}

	existing, _ := s.users.GetByEmail(ctx, input.Email)
	if existing != nil {
		return nil, domain.ErrAccountAlreadyExists
	}

	existingInvite, _ := s.invites.GetByEmail(ctx, input.Email)
	if existingInvite != nil && existingInvite.Status == domain.InvitePending {
		if time.Now().UTC().Before(existingInvite.ExpiresAt) {
			return nil, domain.NewError("invite_already_exists", "An active invite already exists for this email", 409)
		}
	}

	raw, err := s.gen.Generate()
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to generate invite code", 500)
	}

	now := time.Now().UTC()

	invite := &domain.Invite{
		ID:        generateID(),
		Email:     input.Email,
		Code:      hashToken(raw),
		RawCode:   raw,
		CreatedBy: input.AdminID,
		Status:    domain.InvitePending,
		ExpiresAt: now.Add(s.config.InviteTTL),
		CreatedAt: now,
	}

	if err := s.invites.Create(ctx, invite); err != nil {
		return nil, domain.NewError("internal_error", "Failed to create invite", 500)
	}

	if s.mailer != nil {
		code := raw
		url := "https://example.com/invite?code=" + code
		html := "<p>You have been invited. Click <a href=\"" + url + "\">here</a> to accept.</p>"
		text := "You have been invited. Accept here: " + url
		if err := s.mailer.Send(ctx, input.Email, "You're invited to "+s.config.AppName, html, text); err != nil {
			return nil, domain.NewError("email_failed", "Failed to send invite email", 500)
		}
	}

	return invite, nil
}

func (s *InviteService) CompleteInviteRegistration(ctx context.Context, input CompleteInviteInput) (*CompleteInviteResult, *domain.AuthError) {
	if err := s.config.PasswordPolicy.Validate(input.Password); err != nil {
		return nil, err
	}
	if input.Password != input.ConfirmPassword {
		return nil, domain.NewError("passwords_dont_match", "Passwords do not match", 400)
	}

	invite, err := s.invites.GetByCode(ctx, hashToken(input.Code))
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

	existing, _ := s.users.GetByEmail(ctx, invite.Email)
	if existing != nil {
		return nil, domain.ErrAccountAlreadyExists
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to hash password", 500)
	}

	now := time.Now().UTC()

	name := input.Name
	if strings.TrimSpace(name) == "" {
		return nil, domain.NewError("name_required", "Name is required", 400)
	}
	name = strings.TrimSpace(name)

	user := &domain.User{
		ID:           generateID(),
		Email:        invite.Email,
		PasswordHash: hash,
		Name:         name,
		Role:         domain.RoleUser,
		IsVerified:   true,
		VerifiedAt:   &now,
		IsBanned:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, domain.NewError("internal_error", "Failed to create user", 500)
	}

	invite.Status = domain.InviteAccepted
	invite.AcceptedAt = &now
	s.invites.Update(ctx, invite)

	session, rawToken, err := s.sessionSvc.Create(ctx, user.ID, "", "")
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to create session", 500)
	}

	return &CompleteInviteResult{
		User:         user,
		Session:      session,
		SessionToken: rawToken,
	}, nil
}

func (s *InviteService) RevokeInvite(ctx context.Context, inviteID string) *domain.AuthError {
	invite, err := s.invites.GetByID(ctx, inviteID)
	if err != nil || invite == nil {
		return domain.ErrInviteNotFound
	}
	invite.Status = domain.InviteRevoked
	if err := s.invites.Update(ctx, invite); err != nil {
		return domain.NewError("internal_error", "Failed to revoke invite", 500)
	}
	return nil
}

func (s *InviteService) ListInvites(ctx context.Context, offset, limit int) ([]domain.Invite, int, *domain.AuthError) {
	invites, total, err := s.invites.List(ctx, offset, limit)
	if err != nil {
		return nil, 0, domain.NewError("internal_error", "Failed to list invites", 500)
	}
	return invites, total, nil
}

func (s *InviteService) ResendInviteEmail(ctx context.Context, inviteID string) *domain.AuthError {
	if s.mailer == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured", 500)
	}

	invite, err := s.invites.GetByID(ctx, inviteID)
	if err != nil || invite == nil {
		return domain.ErrInviteNotFound
	}

	if invite.Status != domain.InvitePending {
		return domain.NewError("invite_not_pending", "Invite is no longer pending", 400)
	}

	if time.Now().UTC().After(invite.ExpiresAt) {
		return domain.ErrInviteExpired
	}

	// Generate new code so we have the raw token for the link
	raw, err := s.gen.Generate()
	if err != nil {
		return domain.NewError("internal_error", "Failed to generate invite code", 500)
	}

	invite.Code = hashToken(raw)
	if err := s.invites.Update(ctx, invite); err != nil {
		return domain.NewError("internal_error", "Failed to update invite", 500)
	}

	code := raw
	url := "https://example.com/invite?code=" + code
	html := "<p>You have been invited. Click <a href=\"" + url + "\">here</a> to accept.</p>"
	text := "You have been invited. Accept here: " + url
	if err := s.mailer.Send(ctx, invite.Email, "You're invited to "+s.config.AppName, html, text); err != nil {
		return domain.NewError("email_failed", "Failed to send invite email", 500)
	}

	return nil
}
