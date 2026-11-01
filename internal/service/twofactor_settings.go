package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
	"github.com/nazimdjebloun/go-auth/port"
)

func settingsTokenType(action string) (domain.TokenType, error) {
	switch action {
	case "enable":
		return domain.TokenTwoFactorEnable, nil
	case "disable":
		return domain.TokenTwoFactorDisable, nil
	default:
		return "", domain.ErrTwoFactorCodeInvalid
	}
}

// AttachSettingsSessions provides live session lookup for preference confirmations.
func (s *TwoFactorService) AttachSettingsSessions(sessions port.SessionIdentityReader) {
	s.settingsSessions = sessions
}

func (s *TwoFactorService) settingsSession(ctx context.Context, userID, sessionID string) (*domain.Session, error) {
	if s.sessionSvc == nil || s.settingsSessions == nil || sessionID == "" {
		return nil, domain.ErrInvalidCredentials
	}
	session, err := s.settingsSessions.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if err := s.sessionSvc.checkSession(session); err != nil {
		return nil, err
	}
	if session.UserID != userID || !sessioncontext.Matches(ctx, session.TokenHash) {
		return nil, domain.ErrInvalidCredentials
	}
	return session, nil
}

// RequestSettingsChallenge sends a confirmation only for optional settings.
// A live challenge is reused without another email or a fresh guessing budget.
func (s *TwoFactorService) RequestSettingsChallenge(ctx context.Context, input api.TwoFactorSettingsChallengeInput) (*api.ChallengeResult, error) {
	kind, err := settingsTokenType(input.Action)
	if err != nil {
		return nil, err
	}
	if s.config.RequireEmail2FA {
		return nil, domain.ErrTwoFactorAlreadyEnforced
	}
	var user *domain.User
	var token *domain.VerificationToken
	var raw string
	sent := false
	err = s.withTx(ctx, func(txCtx context.Context) error {
		var err error
		user, err = s.users.GetByIDForUpdate(txCtx, input.UserID)
		if err != nil {
			return err
		}
		if user == nil {
			return domain.ErrUserNotFound
		}
		if user.IsBanned {
			return domain.ErrUserBanned
		}
		if s.config.RequireEmailVerification && !user.IsVerified {
			return domain.ErrEmailNotVerified
		}
		token, err = s.tokens.GetLastByUserAndType(txCtx, user.ID, kind)
		if err != nil {
			return err
		}
		session, err := s.settingsSession(txCtx, input.UserID, input.CallerSessionID)
		if err != nil {
			return err
		}
		contextHash := hashToken(session.ID)
		if token != nil && token.UsedAt == nil && token.Email == user.Email && token.ContextHash == contextHash && token.ExpiresAt.After(s.now().UTC()) && !stalePepper(token.CreatedAt, s.config.PepperRotatedAt) {
			return nil
		}
		if s.mailer == nil {
			return domain.ErrEmailNotConfigured
		}
		if len(s.config.OTPPepper) == 0 {
			return domain.ErrInternal
		}
		raw, err = otp.GenerateNumeric(twoFactorCodeLength)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		token = &domain.VerificationToken{ID: generateID(), UserID: &user.ID, Email: user.Email, Type: kind, ContextHash: contextHash, TokenHash: hashOTP(raw, s.config.OTPPepper), CreatedAt: now, ExpiresAt: now.Add(s.config.TwoFactorCodeTTL)}
		sent = true
		return s.tokens.Create(txCtx, token)
	})
	if err != nil {
		return nil, err
	}
	if sent {
		if err := s.send(ctx, user, raw); err != nil {
			if cleanup := discardUndeliveredToken(ctx, s.tokens, token.ID); cleanup != nil {
				return nil, fmt.Errorf("settings proof cleanup: %w", cleanup)
			}
			return nil, err
		}
	}
	return &api.ChallengeResult{ID: token.ID, Sent: sent, ExpiresAt: token.ExpiresAt}, nil
}

func (s *TwoFactorService) authorizeSettingChange(ctx context.Context, userID, password, challengeID, code, sessionID string, kind domain.TokenType) (*domain.User, error) {
	if challengeID == "" {
		return s.authorizeChange(ctx, userID, password)
	}
	if s.config.RequireEmail2FA {
		return nil, domain.ErrTwoFactorAlreadyEnforced
	}
	user, err := s.users.GetByIDForUpdate(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, domain.ErrUserNotFound
	}
	if user.IsBanned {
		return nil, domain.ErrUserBanned
	}
	if s.config.RequireEmailVerification && !user.IsVerified {
		return nil, domain.ErrEmailNotVerified
	}
	session, err := s.settingsSession(ctx, userID, sessionID)
	if err != nil {
		return nil, err
	}
	token, err := s.tokens.GetByID(ctx, challengeID)
	if err != nil {
		return nil, err
	}
	if token == nil || token.Type != kind || token.UserID == nil || *token.UserID != userID || token.ContextHash != hashToken(session.ID) || token.Email != user.Email || token.UsedAt != nil || !token.ExpiresAt.After(s.now().UTC()) || stalePepper(token.CreatedAt, s.config.PepperRotatedAt) {
		return nil, domain.ErrTwoFactorCodeInvalid
	}
	if !verifyOTP(code, token.TokenHash, s.config.OTPPepper) {
		if _, err := s.tokens.IncrementAttempts(ctx, token.ID, maxAttemptsPerChallenge); err != nil {
			return nil, err
		}
		return nil, domain.ErrTwoFactorCodeInvalid
	}
	claimed, err := s.tokens.ConsumeIfValidUnderCap(ctx, port.ConsumeTokenInput{ID: token.ID, TokenHash: token.TokenHash, UserID: user.ID, Type: kind, UsedAt: s.now().UTC()}, maxAttemptsPerChallenge)
	if err != nil {
		return nil, err
	}
	if !claimed {
		return nil, domain.ErrTwoFactorCodeInvalid
	}
	return user, nil
}

// Failed guesses must commit their counter without committing any setting change.
func (s *TwoFactorService) settingsTransaction(ctx context.Context, change func(context.Context) error) error {
	var proofErr error
	err := s.withTx(ctx, func(txCtx context.Context) error {
		err := change(txCtx)
		if errors.Is(err, domain.ErrTwoFactorCodeInvalid) {
			proofErr = err
			return nil
		}
		return err
	})
	if err != nil {
		var authErr *domain.AuthError
		if errors.As(err, &authErr) {
			return err
		}
		return fmt.Errorf("two-factor settings: %w: %w", domain.ErrInternal, err)
	}
	return proofErr
}
