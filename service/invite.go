package service

import (
	"context"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type InviteService struct {
	users    port.UserRepository
	sessions port.SessionRepository
	invites  port.InviteRepository
	tokens   port.TokenRepository
	hasher   port.Hasher
	gen      port.TokenGenerator
	email    port.EmailSender
	config   Config
}

func NewInviteService(
	users port.UserRepository,
	sessions port.SessionRepository,
	invites port.InviteRepository,
	tokens port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	email port.EmailSender,
	config Config,
) *InviteService {
	return &InviteService{
		users:    users,
		sessions: sessions,
		invites:  invites,
		tokens:   tokens,
		hasher:   hasher,
		gen:      gen,
		email:    email,
		config:   config,
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

	raw, hash, err := s.gen.Generate()
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to generate invite code", 500)
	}

	now := time.Now().UTC()

	// Use first 8 chars of raw hash as a short readable invite code
	shortCode := raw[:8]

	invite := &domain.Invite{
		ID:        generateID(),
		Email:     input.Email,
		Code:      shortCode,
		CreatedBy: input.AdminID,
		Status:    domain.InvitePending,
		ExpiresAt: now.Add(s.config.InviteTTL),
		CreatedAt: now,
	}

	if err := s.invites.Create(ctx, invite); err != nil {
		return nil, domain.NewError("internal_error", "Failed to create invite", 500)
	}

	// Store full token for verification flow
	token := &domain.VerificationToken{
		ID:        generateID(),
		Email:     input.Email,
		TokenHash: hash,
		Type:      domain.TokenInviteVerify,
		ExpiresAt: now.Add(s.config.InviteTTL),
	}
	s.tokens.Create(ctx, token)

	if s.email != nil {
		data := map[string]any{
			"Code":      shortCode,
			"Email":     input.Email,
			"AppName":   s.config.AppName,
			"ExpiresIn": s.config.InviteTTL.String(),
		}
		s.email.Send(ctx, port.EmailData{
			To:           input.Email,
			Subject:      "You're invited!",
			TemplateName: "invite_email",
			TemplateData: data,
		})
	}

	return invite, nil
}

func (s *InviteService) VerifyInvite(ctx context.Context, input VerifyInviteInput) *domain.AuthError {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	invite, err := s.invites.GetByCode(ctx, input.Code)
	if err != nil || invite == nil {
		return domain.ErrInviteNotFound
	}

	if !strings.EqualFold(invite.Email, input.Email) {
		return domain.ErrInviteNotFound
	}

	if invite.Status == domain.InviteAccepted {
		return domain.ErrInviteAlreadyUsed
	}
	if invite.Status == domain.InviteRevoked {
		return domain.ErrInviteRevoked
	}
	if time.Now().UTC().After(invite.ExpiresAt) {
		invite.Status = domain.InviteExpired
		s.invites.Update(ctx, invite)
		return domain.ErrInviteExpired
	}

	existing, _ := s.users.GetByEmail(ctx, input.Email)
	if existing != nil {
		return domain.ErrAccountAlreadyExists
	}

	raw, hash, err := s.gen.Generate()
	if err != nil {
		return domain.NewError("internal_error", "Failed to generate verification code", 500)
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		Email:     input.Email,
		TokenHash: hash,
		Type:      domain.TokenInviteVerify,
		ExpiresAt: now.Add(s.config.VerificationCodeTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		return domain.NewError("internal_error", "Failed to store verification code", 500)
	}

	if s.email != nil {
		data := map[string]any{
			"Code":      raw,
			"Email":     input.Email,
			"AppName":   s.config.AppName,
			"ExpiresIn": s.config.VerificationCodeTTL.String(),
		}
		s.email.Send(ctx, port.EmailData{
			To:           input.Email,
			Subject:      "Your verification code",
			TemplateName: "invite_verify",
			TemplateData: data,
		})
	}

	return nil
}

func (s *InviteService) CompleteInviteRegistration(ctx context.Context, input CompleteInviteInput) (*CompleteInviteResult, *domain.AuthError) {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	if err := validatePassword(input.Password); err != nil {
		return nil, err
	}

	tokenHash := s.gen.Hash(input.VerificationCode)
	token, err := s.tokens.GetByHash(ctx, tokenHash)
	if err != nil || token == nil {
		return nil, domain.ErrTokenInvalid
	}

	if token.Type != domain.TokenInviteVerify {
		return nil, domain.ErrTokenInvalid
	}

	if !strings.EqualFold(token.Email, input.Email) {
		return nil, domain.ErrTokenInvalid
	}

	if token.UsedAt != nil {
		return nil, domain.ErrTokenAlreadyUsed
	}

	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, domain.ErrTokenExpired
	}

	invite, err := s.invites.GetByEmail(ctx, input.Email)
	if err != nil || invite == nil {
		return nil, domain.ErrInviteNotFound
	}

	if invite.Status != domain.InvitePending {
		return nil, domain.ErrInviteAlreadyUsed
	}

	existing, _ := s.users.GetByEmail(ctx, input.Email)
	if existing != nil {
		return nil, domain.ErrAccountAlreadyExists
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to hash password", 500)
	}

	now := time.Now().UTC()
	role := domain.RoleUser
	for _, adminEmail := range s.config.AdminEmails {
		if strings.EqualFold(input.Email, adminEmail) {
			role = domain.RoleAdmin
			break
		}
	}

	if input.Name == "" {
		input.Name = input.Email[:strings.Index(input.Email, "@")]
	}

	user := &domain.User{
		ID:           generateID(),
		Email:        input.Email,
		PasswordHash: hash,
		Name:         input.Name,
		Role:         role,
		IsVerified:   true, // auto-verified via invite
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

	s.tokens.MarkUsed(ctx, token.ID)

	raw, sessionHash, err := s.gen.Generate()
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to generate session", 500)
	}

	session := &domain.Session{
		ID:         generateID(),
		UserID:     user.ID,
		TokenHash:  sessionHash,
		ExpiresAt:  now.Add(s.config.SessionTTL),
		CreatedAt:  now,
		LastUsedAt: now,
	}

	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, domain.NewError("internal_error", "Failed to create session", 500)
	}

	return &CompleteInviteResult{
		User:         user,
		Session:      session,
		SessionToken: raw,
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
	if s.email == nil {
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

	data := map[string]any{
		"Code":      invite.Code,
		"Email":     invite.Email,
		"AppName":   s.config.AppName,
		"ExpiresIn": s.config.InviteTTL.String(),
	}

	if err := s.email.Send(ctx, port.EmailData{
		To:           invite.Email,
		Subject:      "You're invited!",
		TemplateName: "invite_email",
		TemplateData: data,
	}); err != nil {
		return domain.NewError("email_failed", "Failed to send invite email", 500)
	}

	return nil
}
