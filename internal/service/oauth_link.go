package service

import (
	"context"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
	"github.com/nazimdjebloun/go-auth/port"
)

// Exchange runs before this short transaction. Lock user -> session so reset,
// email replacement and revocation cannot invalidate the final authority check
// between that check and installing a new authentication method.
func (s *OAuthService) finalizeLink(ctx context.Context, input api.OAuthCallbackInput, state *domain.VerificationToken, sessionID string, profile *port.OAuthProfile) error {
	return s.txManager.WithTx(ctx, func(ctx context.Context) error {
		user, err := s.userRepo.GetByIDForUpdate(ctx, *state.UserID)
		if err != nil {
			return fmt.Errorf("oauth link: lock user: %w", err)
		}
		if user == nil {
			return domain.NewError("unauthorized", "Authentication required")
		}
		if user.IsBanned {
			return domain.ErrUserBanned
		}
		if s.config.RequireEmailVerification && !user.IsVerified {
			return domain.ErrEmailNotVerified
		}
		session, err := s.sessionSvc.repo.LockByID(ctx, sessionID)
		if err != nil {
			return fmt.Errorf("oauth link: lock session: %w", err)
		}
		tokenHash := hashToken(input.SessionToken)
		if session == nil || session.UserID != user.ID || !sessioncontext.Matches(ctx, input.SessionToken) ||
			subtle.ConstantTimeCompare([]byte(session.TokenHash), []byte(tokenHash)) != 1 {
			return domain.NewError("unauthorized", "Authentication required")
		}
		if err := s.sessionSvc.checkSession(session); err != nil {
			return domain.NewError("unauthorized", "Authentication required")
		}
		claimed, err := s.tokenRepo.GetByID(ctx, state.ID)
		if err != nil {
			return fmt.Errorf("oauth link: reload state: %w", err)
		}
		if claimed == nil || claimed.Type != domain.TokenOAuthState || claimed.UserID == nil ||
			*claimed.UserID != user.ID || claimed.UsedAt == nil || claimed.TokenHash != state.TokenHash ||
			claimed.Email != tokenHash || (claimed.ContextHash != "" && claimed.ContextHash != hashToken(input.Provider)) {
			return domain.NewError("invalid_state", "Invalid or expired OAuth state")
		}
		if !time.Now().UTC().Before(claimed.ExpiresAt) {
			return domain.NewError("state_expired", "OAuth state token has expired")
		}
		_, err = s.createProviderAccount(ctx, user.ID, profile)
		return err
	})
}
