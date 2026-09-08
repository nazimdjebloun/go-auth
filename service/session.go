package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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
	SameSite          http.SameSite
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
		SameSite:          http.SameSiteLaxMode,
		Duration:          7 * 24 * time.Hour,
		IdleTTL:           7 * 24 * time.Hour,
		RefreshTTL:        30 * 24 * time.Hour,
		GraceWindow:       5 * time.Second,
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

// SessionResult bundles a session with the raw tokens issued alongside it.
// Only the hashes are ever persisted, so Create and RefreshSession are the
// only places the raw SessionToken/RefreshToken values exist — this is how
// they reach the caller (an HTTP handler that cookies them, or a
// programmatic caller that stores them directly).
type SessionResult struct {
	Session      *domain.Session
	SessionToken string
	RefreshToken string
}

func (s *SessionService) Create(ctx context.Context, userID, ip, userAgent string) (*SessionResult, error) {
	sessionToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("session create token: %w", err)
	}

	refreshToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("session create refresh: %w", err)
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
		return nil, fmt.Errorf("session create: %w", err)
	}

	s.log.Info("session created", "user_id", userID, "session_id", session.ID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewSessionEvent(audit.EventSessionCreated, userID, session.ID, net.ParseIP(ip), userAgent))
	}

	return &SessionResult{Session: session, SessionToken: sessionToken, RefreshToken: refreshToken}, nil
}

func (s *SessionService) RefreshSession(ctx context.Context, rawRefreshToken string) (*SessionResult, error) {
	hash := hashToken(rawRefreshToken)

	newSessionToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("refresh gen session: %w", err)
	}

	newRefreshToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("refresh gen refresh: %w", err)
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
		// A reused refresh token is theft-shaped, not just a rejected request
		// — the repository has already revoked the compromised session by the
		// time this returns. Publish the signal, then normalize to the same
		// domain.ErrSessionRevoked a client would see for any other revoked
		// session, so this doesn't change the public API's error contract.
		var reused *port.ErrRefreshTokenReused
		if errors.As(err, &reused) {
			s.log.Warn("refresh token reuse detected", "user_id", reused.UserID, "session_id", reused.SessionID)
			if s.audit != nil {
				s.audit.Publish(ctx, audit.NewSessionReuseDetectedEvent(reused.UserID, reused.SessionID))
			}
			return nil, domain.ErrSessionRevoked
		}
		return nil, err
	}

	s.log.Info("refresh token rotated", "user_id", session.UserID, "session_id", session.ID)
	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewSessionEvent(audit.EventSessionRefreshed, session.UserID, session.ID, nil, ""))
	}
	return &SessionResult{Session: session, SessionToken: newSessionToken, RefreshToken: newRefreshToken}, nil
}

// checkSession applies the liveness rules to an already-loaded session. Shared
// by Validate and ValidateWithUser so the two can never disagree about what
// counts as a usable session.
func (s *SessionService) checkSession(session *domain.Session) error {
	if session == nil {
		return domain.ErrSessionNotFound
	}
	if session.IsRevoked {
		return domain.ErrSessionExpired
	}
	now := time.Now().UTC()
	if now.After(session.ExpiresAt) {
		return domain.ErrSessionExpired
	}
	if s.config.IdleTTL > 0 && now.After(session.LastActiveAt.Add(s.config.IdleTTL)) {
		return domain.ErrSessionExpired
	}
	return nil
}

func (s *SessionService) Validate(ctx context.Context, token string) (*domain.Session, error) {
	session, err := s.repo.GetByTokenHash(ctx, hashToken(token))
	if err != nil {
		return nil, fmt.Errorf("session validate: %w", err)
	}
	if err := s.checkSession(session); err != nil {
		return nil, err
	}
	return session, nil
}

// ValidateWithUser is Validate plus the session's owning user, resolved in one
// query rather than two. It is what AuthMiddleware uses: that path needs both
// on every authenticated request, and the user is always the one the session
// points at.
//
// A session with no matching user row comes back as ErrSessionNotFound — the
// join is inner, so an orphaned session is indistinguishable from a missing
// one, and both are authentication failures.
func (s *SessionService) ValidateWithUser(ctx context.Context, token string) (*domain.Session, *domain.User, error) {
	session, user, err := s.repo.GetByTokenHashWithUser(ctx, hashToken(token))
	if err != nil {
		return nil, nil, fmt.Errorf("session validate: %w", err)
	}
	if err := s.checkSession(session); err != nil {
		return nil, nil, err
	}
	return session, user, nil
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

func (s *SessionService) RevokeByIDForUser(ctx context.Context, id, userID string) (bool, error) {
	ok, err := s.repo.RevokeByIDForUser(ctx, id, userID)
	if err != nil {
		return false, fmt.Errorf("session revoke by id: %w", err)
	}
	return ok, nil
}

func (s *SessionService) RevokeManyForUser(ctx context.Context, ids []string, userID string) (int, error) {
	n, err := s.repo.RevokeManyForUser(ctx, ids, userID)
	if err != nil {
		return 0, fmt.Errorf("session revoke many: %w", err)
	}
	return n, nil
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

func (s *SessionService) List(ctx context.Context, userID string, offset, limit int) ([]domain.Session, int, error) {
	return s.repo.ListByUserID(ctx, userID, offset, limit)
}

func (s *SessionService) ListAll(ctx context.Context, userID string) ([]domain.Session, error) {
	return s.repo.ListAllByUserID(ctx, userID)
}

func (s *SessionService) Config() SessionConfig {
	return s.config
}

func IsSessionError(err error) bool {
	return errors.Is(err, domain.ErrSessionNotFound) || errors.Is(err, domain.ErrSessionExpired)
}
