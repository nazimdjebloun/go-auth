package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type SessionService struct {
	repo     port.SessionRepository
	tokenGen port.TokenGenerator
	config   SessionConfig
	log      *slog.Logger
	audit    AuditPublisher
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
	MaxLifetime       time.Duration // 0 = no max lifetime
	GraceWindow       time.Duration
	TouchDebounce     time.Duration // min interval between last_active_at updates
	Logger            *slog.Logger
	Audit             AuditPublisher
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
		TouchDebounce:     5 * time.Minute,
	}
}

func NewSessionService(repo port.SessionRepository, tokenGen port.TokenGenerator, config SessionConfig) *SessionService {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &SessionService{repo: repo, tokenGen: tokenGen, config: config, log: logger, audit: config.Audit}
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
		ParsedUA:            domain.ParseUserAgent(userAgent),
		ExpiresAt:           now.Add(s.config.Duration),
		RefreshExpiresAt:    now.Add(s.config.RefreshTTL),
		CreatedAt:           now,
		LastActiveAt:        now,
	}

	if err := s.repo.Create(ctx, session); err != nil {
		return nil, "", "", fmt.Errorf("session create: %w", err)
	}

	s.log.Info("session created", "user_id", userID, "session_id", session.ID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewSessionEvent(audit.EventSessionCreated, userID, session.ID, net.ParseIP(ip), userAgent))
	}

	return session, sessionToken, refreshToken, nil
}

func (s *SessionService) RefreshSession(ctx context.Context, rawRefreshToken string) (*domain.Session, string, string, error) {
	hash := hashToken(rawRefreshToken)

	newSessionToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, "", "", fmt.Errorf("refresh gen session: %w", err)
	}

	newRefreshToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, "", "", fmt.Errorf("refresh gen refresh: %w", err)
	}

	now := time.Now().UTC()
	session, err := s.repo.UpdateRefreshToken(ctx, port.UpdateRefreshInput{
		OldRefreshHash: hash,
		NewTokenHash:   hashToken(newSessionToken),
		NewRefreshHash: hashToken(newRefreshToken),
		NewExpiresAt:   now.Add(s.config.Duration),
		RotatedAt:      now,
		MaxLifetime:    s.config.MaxLifetime,
		GraceWindow:    s.config.GraceWindow,
	})
	if err != nil {
		return nil, "", "", err
	}

	s.log.Info("refresh token rotated", "user_id", session.UserID, "session_id", session.ID)
	return session, newSessionToken, newRefreshToken, nil
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

func (s *SessionService) Touch(ctx context.Context, token string, lastActiveAt time.Time) error {
	if s.config.TouchDebounce > 0 && time.Since(lastActiveAt) < s.config.TouchDebounce {
		return nil
	}
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
	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewSessionEvent(audit.EventSessionRevokedAll, userID, "", nil, ""))
	}
	return nil
}

func (s *SessionService) RevokeAllExcept(ctx context.Context, userID string, exceptSessionID string) error {
	if err := s.repo.DeleteAllForUserExcept(ctx, userID, exceptSessionID); err != nil {
		return fmt.Errorf("session revoke all except: %w", err)
	}
	return nil
}

func (s *SessionService) List(ctx context.Context, userID string) ([]domain.Session, int, error) {
	return s.repo.ListByUserID(ctx, userID, 0, 0)
}

func (s *SessionService) Config() SessionConfig {
	return s.config
}

func IsSessionError(err error) bool {
	return errors.Is(err, domain.ErrSessionNotFound) || errors.Is(err, domain.ErrSessionExpired)
}
