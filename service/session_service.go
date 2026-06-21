package service

import (
	"context"
	"errors"
	"fmt"
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
	CookieName   string
	Domain       string
	Path         string
	Secure       bool
	SameSite     int
	Duration     time.Duration
	IdleTTL      time.Duration
}

func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		CookieName: "goauth_session",
		Path:       "/",
		Secure:     true,
		SameSite:   2, // http.SameSiteLaxMode
		Duration:   7 * 24 * time.Hour,
		IdleTTL:    7 * 24 * time.Hour,
	}
}

func NewSessionService(repo port.SessionRepository, tokenGen port.TokenGenerator, config SessionConfig) *SessionService {
	return &SessionService{repo: repo, tokenGen: tokenGen, config: config}
}

func (s *SessionService) Create(ctx context.Context, userID, ip, userAgent string) (*domain.Session, string, error) {
	token, err := s.tokenGen.Generate()
	if err != nil {
		return nil, "", fmt.Errorf("session create token: %w", err)
	}

	now := time.Now().UTC()
	session := &domain.Session{
		ID:           uuid.New().String(),
		UserID:       userID,
		TokenHash:    hashToken(token),
		IP:           ip,
		UserAgent:    userAgent,
		ExpiresAt:    now.Add(s.config.Duration),
		CreatedAt:    now,
		LastActiveAt: now,
	}

	if err := s.repo.Create(ctx, session); err != nil {
		return nil, "", fmt.Errorf("session create: %w", err)
	}

	return session, token, nil
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
