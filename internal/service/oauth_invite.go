package service

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
	"github.com/nazimdjebloun/go-auth/port"
)

// AttachInvites supplies account invitations before requests are served.
func (s *OAuthService) AttachInvites(invites port.InviteRepository) { s.invites = invites }

func (s *OAuthService) pendingInvite(ctx context.Context, codeHash string) (*domain.Invite, error) {
	if !s.config.InviteSignup || !s.config.OAuth || s.config.OAuthAuthenticationDisabled {
		return nil, domain.ErrMethodDisabled
	}
	if s.invites == nil {
		return nil, domain.ErrInternal
	}
	invite, err := s.invites.GetByCode(ctx, codeHash)
	if err != nil {
		return nil, fmt.Errorf("oauth invitation: lookup: %w", err)
	}
	if invite == nil {
		return nil, domain.ErrInviteNotFound
	}
	if invite.Status != domain.InvitePending {
		return nil, domain.ErrInviteAlreadyUsed
	}
	if !invite.ExpiresAt.After(time.Now().UTC()) {
		return nil, domain.ErrInviteExpired
	}
	return invite, nil
}

// InitiateInvite associates the invitation hash with the server-owned OAuth state.
func (s *OAuthService) InitiateInvite(ctx context.Context, input api.OAuthInviteInput) (*api.OAuthInitiation, error) {
	if sessioncontext.Current(ctx) == sessioncontext.Admin {
		return nil, domain.ErrInvalidSessionContext
	}
	if input.InviteToken == "" {
		return nil, domain.ErrInviteNotFound
	}
	invite, err := s.pendingInvite(ctx, hashToken(input.InviteToken))
	if err != nil {
		return nil, err
	}
	return s.initiate(ctx, input.Provider, invite.Code)
}

func (s *OAuthService) prepareInviteVerification(ctx context.Context, info *port.OAuthProfile, invite *domain.Invite) (*api.OAuthCallbackResult, error) {
	if s.encryptor == nil || s.twoFactorSvc == nil {
		return nil, domain.ErrInternal
	}
	profile := *info
	profile.Raw = nil
	data, err := json.Marshal(profile) //nolint:gosec // G117: provider credentials are encrypted immediately below, never stored as JSON.
	if err != nil {
		return nil, err
	}
	payload, err := s.encryptor.Encrypt(string(data))
	if err != nil {
		return nil, err
	}
	raw, err := otp.GenerateNumeric(twoFactorCodeLength)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	ttl := s.twoFactorSvc.config.VerificationCodeTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	expires := now.Add(ttl)
	if invite.ExpiresAt.Before(expires) {
		expires = invite.ExpiresAt
	}
	token := &domain.VerificationToken{ID: generateID(), Email: invite.Email,
		Type: domain.TokenInviteVerify, TokenHash: hashOTP(raw, s.twoFactorSvc.config.OTPPepper),
		ContextHash: invite.Code, EncryptedPayload: payload, CreatedAt: now, ExpiresAt: expires}
	if err := s.tokenRepo.Create(ctx, token); err != nil {
		return nil, err
	}
	if err := s.sendInviteVerification(ctx, invite.Email, raw, ttl); err != nil {
		if cleanup := discardUndeliveredToken(ctx, s.tokenRepo, token.ID); cleanup != nil {
			return nil, fmt.Errorf("oauth invite delivery cleanup: %w", cleanup)
		}
		return nil, err
	}
	return api.NewOAuthCallbackResult(api.OAuthCallbackResult{RequiresInviteVerification: true, InviteChallengeID: token.ID, InviteExpiresAt: token.ExpiresAt}, s.twoFactorSvc.bindingToken("oauth-invite."+token.ID)), nil
}

// VerifyInviteEmail verifies address ownership before account creation. The
// profile is encrypted at rest; invite claim, proof claim and account creation
// share a transaction so neither credential is consumed on a failed creation.
func (s *OAuthService) VerifyInviteEmail(ctx context.Context, input api.OAuthInviteVerifyInput) (*api.OAuthCallbackResult, error) {
	if sessioncontext.Current(ctx) == sessioncontext.Admin {
		return nil, domain.ErrInvalidSessionContext
	}
	if s.config.OAuthAuthenticationDisabled || !s.config.OAuth || !s.config.InviteSignup {
		return nil, domain.ErrMethodDisabled
	}
	if s.twoFactorSvc == nil || s.encryptor == nil {
		return nil, domain.ErrInternal
	}
	want := s.twoFactorSvc.bindingToken("oauth-invite." + input.ChallengeID)
	if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(input.BindingToken)) != 1 {
		return nil, domain.ErrVerificationCodeInvalid
	}
	token, err := s.tokenRepo.GetByID(ctx, input.ChallengeID)
	if err != nil {
		return nil, err
	}
	if token == nil || token.Type != domain.TokenInviteVerify || token.UserID != nil || token.UsedAt != nil || !token.ExpiresAt.After(time.Now().UTC()) || stalePepper(token.CreatedAt, s.twoFactorSvc.config.PepperRotatedAt) {
		return nil, domain.ErrVerificationCodeInvalid
	}
	if !verifyOTP(input.Code, token.TokenHash, s.twoFactorSvc.config.OTPPepper) {
		if _, err := s.tokenRepo.IncrementAttempts(ctx, token.ID, maxAttemptsPerChallenge); err != nil {
			return nil, err
		}
		return nil, domain.ErrVerificationCodeInvalid
	}
	invite, err := s.pendingInvite(ctx, token.ContextHash)
	if err != nil {
		return nil, err
	}
	data, err := s.encryptor.Decrypt(token.EncryptedPayload)
	if err != nil {
		return nil, domain.ErrVerificationCodeInvalid
	}
	var info port.OAuthProfile
	if err := json.Unmarshal([]byte(data), &info); err != nil {
		return nil, domain.ErrVerificationCodeInvalid
	}
	if info.Email != token.Email || token.Email != invite.Email {
		return nil, domain.ErrVerificationCodeInvalid
	}
	if _, err := s.getProvider(info.Provider); err != nil {
		return nil, err
	}
	info.EmailVerified = true
	var user *domain.User
	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		claimed, err := s.tokenRepo.ConsumeIfValidUnderCap(txCtx, port.ConsumeTokenInput{ID: token.ID, TokenHash: token.TokenHash, Type: token.Type, UsedAt: time.Now().UTC()}, maxAttemptsPerChallenge)
		if err != nil {
			return err
		}
		if !claimed {
			return domain.ErrVerificationCodeInvalid
		}
		user, err = s.createOAuthAccount(txCtx, api.OAuthCallbackInput{Provider: info.Provider, IP: input.IP, UserAgent: input.UserAgent}, &info, invite)
		return err
	})
	if err != nil {
		return nil, err
	}
	result, err := s.completeOAuthLogin(ctx, user, info.Provider, input.IP, input.UserAgent, true)
	if result != nil {
		result.IsNewUser = true
	}
	return result, err
}

func (s *OAuthService) sendInviteVerification(ctx context.Context, email, code string, ttl time.Duration) error {
	svc := s.twoFactorSvc
	if svc.mailer == nil {
		return domain.ErrEmailNotConfigured
	}
	result, err := svc.templates.Render(port.VerificationData{AppName: s.config.AppName, Code: code, ExpiresIn: ttl})
	if err != nil {
		return err
	}
	return svc.mailer.Send(ctx, email, result.Subject, result.HTML, result.Text)
}
