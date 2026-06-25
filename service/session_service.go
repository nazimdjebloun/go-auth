package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type SessionService struct {
	repo     port.SessionRepository
	tokenGen port.TokenGenerator
	config   SessionConfig
}

type SessionConfig struct {
	CookieName        string
	RefreshCookieName string
	Domain            string
	Path              string
	Secure            bool
	SameSite          int
	Duration          time.Duration
	IdleTTL           time.Duration
	RefreshTTL        time.Duration
}

func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		CookieName:        "goauth_session",
		RefreshCookieName: "goauth_refresh",
		Path:              "/",
		Secure:            true,
		SameSite:          2,
		Duration:          7 * 24 * time.Hour,
		IdleTTL:           7 * 24 * time.Hour,
		RefreshTTL:        30 * 24 * time.Hour,
	}
}

func NewSessionService(repo port.SessionRepository, tokenGen port.TokenGenerator, config SessionConfig) *SessionService {
	return &SessionService{repo: repo, tokenGen: tokenGen, config: config}
}

func (s *SessionService) Create(ctx context.Context, userID, ip, userAgent string) (*domain.Session, string, string, error) {
	sessionToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, "", "", fmt.Errorf("session create token: %w", err)
	}

	refreshToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, "", "", fmt.Errorf("session create refresh: %w", err)
	}

	now := time.Now().UTC()
	session := &domain.Session{
		ID:                  uuid.New().String(),
		UserID:              userID,
		TokenHash:           hashToken(sessionToken),
		RefreshTokenHash:    hashToken(refreshToken),
		PreviousRefreshHash: "",
		IP:                  ip,
		UserAgent:           userAgent,
		ExpiresAt:           now.Add(s.config.Duration),
		RefreshExpiresAt:    now.Add(s.config.RefreshTTL),
		CreatedAt:           now,
		LastActiveAt:        now,
	}

	if err := s.repo.Create(ctx, session); err != nil {
		return nil, "", "", fmt.Errorf("session create: %w", err)
	}

	log.Printf("session created: user_id=%s session_id=%s", userID, session.ID)
	return session, sessionToken, refreshToken, nil
}

func (s *SessionService) RefreshSession(ctx context.Context, rawRefreshToken string) (*domain.Session, string, string, error) {
	hash := hashToken(rawRefreshToken)

	session, err := s.repo.LockAndGetByRefreshHash(ctx, hash)
	if err != nil {
		return nil, "", "", fmt.Errorf("refresh lookup: %w", err)
	}
	if session == nil {
		if reused, reuseErr := s.repo.GetByPreviousRefreshHash(ctx, hash); reuseErr == nil && reused != nil {
			s.handleReuseDetection(ctx, reused)
			return nil, "", "", domain.ErrSessionRevoked
		}
		return nil, "", "", domain.ErrInvalidRefreshToken
	}

	now := time.Now().UTC()

	if session.IsRevoked || now.After(session.ExpiresAt) {
		return nil, "", "", domain.ErrSessionExpired
	}

	if now.After(session.RefreshExpiresAt) {
		return nil, "", "", domain.ErrRefreshExpired
	}

	newSessionToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, "", "", fmt.Errorf("refresh gen session: %w", err)
	}

	newRefreshToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, "", "", fmt.Errorf("refresh gen refresh: %w", err)
	}

	rows, err := s.repo.UpdateRefreshToken(ctx, port.UpdateRefreshInput{
		SessionID:        session.ID,
		OldRefreshHash:   hash,
		NewTokenHash:     hashToken(newSessionToken),
		NewRefreshHash:   hashToken(newRefreshToken),
		PreviousHash:     session.RefreshTokenHash,
		NewExpiresAt:     now.Add(s.config.Duration),
		NewRefreshExpiry: now.Add(s.config.RefreshTTL),
		RotatedAt:        now,
	})
	if err != nil {
		return nil, "", "", fmt.Errorf("refresh update: %w", err)
	}
	if rows == 0 {
		return nil, "", "", domain.ErrInvalidRefreshToken
	}

	log.Printf("refresh token rotated: user_id=%s session_id=%s", session.UserID, session.ID)
	session.TokenHash = hashToken(newSessionToken)
	session.RefreshTokenHash = hashToken(newRefreshToken)
	session.PreviousRefreshHash = hash
	session.RefreshRotatedAt = &now
	return session, newSessionToken, newRefreshToken, nil
}

func (s *SessionService) handleReuseDetection(ctx context.Context, session *domain.Session) {
	log.Printf("WARN: refresh token reuse detected — possible token theft: user_id=%s session_id=%s", session.UserID, session.ID)
	if err := s.repo.Revoke(ctx, session.ID); err != nil {
		log.Printf("ERROR: failed to revoke session on reuse detection: %v", err)
	}
}

func (s *SessionService) Validate(ctx context.Context, token string) (*domain.Session, error) {
	session, err := s.repo.GetByTokenHash(ctx, hashToken(token))
	if err != nil {
		return nil, fmt.Errorf("session validate: %w", err)
	}
	if session == nil {
		return nil, domain.ErrSessionNotFound
	}
	if session.IsRevoked {
		return nil, domain.ErrSessionExpired
	}
	if time.Now().UTC().After(session.ExpiresAt) {
		return nil, domain.ErrSessionExpired
	}
	if s.config.IdleTTL > 0 && time.Now().UTC().After(session.LastActiveAt.Add(s.config.IdleTTL)) {
		return nil, domain.ErrSessionExpired
	}
	return session, nil
}

func (s *SessionService) Touch(ctx context.Context, token string) error {
	return s.repo.UpdateLastActiveAt(ctx, hashToken(token))
}

func (s *SessionService) Revoke(ctx context.Context, token string) error {
	if err := s.repo.Delete(ctx, hashToken(token)); err != nil {
		return fmt.Errorf("session revoke: %w", err)
	}
	return nil
}

func (s *SessionService) RevokeByID(ctx context.Context, id string) error {
	if err := s.repo.DeleteByID(ctx, id); err != nil {
		return fmt.Errorf("session revoke by id: %w", err)
	}
	return nil
}

func (s *SessionService) RevokeAll(ctx context.Context, userID string) error {
	if err := s.repo.DeleteAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("session revoke all: %w", err)
	}
	return nil
}

func (s *SessionService) RevokeAllExcept(ctx context.Context, userID string, exceptSessionID string) error {
	if err := s.repo.DeleteAllForUserExcept(ctx, userID, exceptSessionID); err != nil {
		return fmt.Errorf("session revoke all except: %w", err)
	}
	return nil
}

func (s *SessionService) List(ctx context.Context, userID string) ([]domain.Session, error) {
	return s.repo.ListByUserID(ctx, userID)
}

func (s *SessionService) Config() SessionConfig {
	return s.config
}

func IsSessionError(err error) bool {
	return errors.Is(err, domain.ErrSessionNotFound) || errors.Is(err, domain.ErrSessionExpired)
}
