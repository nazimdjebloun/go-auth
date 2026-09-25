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
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// SessionService manages user sessions.
type SessionService struct {
	repo      port.SessionRepository
	tokenGen  port.TokenGenerator
	config    SessionConfig
	log       *slog.Logger
	audit     AuditPublisher
	txManager port.TxManager
	now       func() time.Time
}

// SessionConfig configures session lifetimes and token rotation.
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

// DefaultSessionConfig returns the default session settings.
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

// NewSessionService returns a session service.
func NewSessionService(repo port.SessionRepository, tokenGen port.TokenGenerator, config SessionConfig) *SessionService {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &SessionService{repo: repo, tokenGen: tokenGen, config: config, log: logger, audit: config.Audit, now: time.Now}
}

// AttachTxManager wires the transaction manager used to commit session
// mutations with the audit records that describe them. Called once by the
// library wiring before requests are served. Directly constructed services
// without a manager retain the legacy autocommit behavior used by lightweight
// tests and custom embeddings.
func (s *SessionService) AttachTxManager(tm port.TxManager) {
	s.txManager = tm
}

func (s *SessionService) withTx(ctx context.Context, fn func(context.Context) error) error {
	if s.txManager == nil {
		return fn(ctx)
	}
	return s.txManager.WithTx(ctx, fn)
}

// Create creates a user session.
func (s *SessionService) Create(ctx context.Context, userID, ip, userAgent string) (*api.SessionResult, error) {
	sessionToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("session create token: %w", err)
	}

	refreshToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("session create refresh: %w", err)
	}

	now := s.now().UTC()
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

	err = s.withTx(ctx, func(txCtx context.Context) error {
		if err := s.repo.Create(txCtx, session); err != nil {
			return fmt.Errorf("session create: %w", err)
		}
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewSessionEvent(audit.EventSessionCreated, userID, session.ID, net.ParseIP(ip), userAgent)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	s.log.Info("session created", "user_id", userID, "session_id", session.ID)

	return &api.SessionResult{Session: session, SessionToken: sessionToken, RefreshToken: refreshToken}, nil
}

// RefreshSession rotates a session using its refresh token.
func (s *SessionService) RefreshSession(ctx context.Context, rawRefreshToken string) (*api.SessionResult, error) {
	hash := hashToken(rawRefreshToken)

	newSessionToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("refresh gen session: %w", err)
	}

	newRefreshToken, err := s.tokenGen.Generate()
	if err != nil {
		return nil, fmt.Errorf("refresh gen refresh: %w", err)
	}

	now := s.now().UTC()
	var session *domain.Session
	var reused *port.ErrRefreshTokenReused
	err = s.withTx(ctx, func(txCtx context.Context) error {
		rotated, rotateErr := s.repo.UpdateRefreshToken(txCtx, port.UpdateRefreshInput{
			OldRefreshHash: hash,
			NewTokenHash:   hashToken(newSessionToken),
			NewRefreshHash: hashToken(newRefreshToken),
			NewExpiresAt:   now.Add(s.config.Duration),
			RotatedAt:      now,
			MaxLifetime:    s.config.MaxLifetime,
			IdleTTL:        s.config.IdleTTL,
			GraceWindow:    s.config.GraceWindow,
		})
		if errors.As(rotateErr, &reused) {
			// Reuse detection deletes the session. Commit that deletion even
			// though the caller must receive a revoked-session error.
			return nil
		}
		if rotateErr != nil {
			return rotateErr
		}
		if s.audit != nil {
			if recordErr := s.audit.Record(txCtx, audit.NewSessionEvent(audit.EventSessionRefreshed, rotated.UserID, rotated.ID, nil, "")); recordErr != nil {
				return recordErr
			}
		}
		session = rotated
		return nil
	})
	if err != nil {
		return nil, err
	}
	if reused != nil {
		s.log.Warn("refresh token reuse detected", "user_id", reused.UserID, "session_id", reused.SessionID)
		if s.audit != nil {
			if recordErr := s.audit.Record(ctx, audit.NewSessionReuseDetectedEvent(reused.UserID, reused.SessionID)); recordErr != nil {
				return nil, recordErr
			}
		}
		return nil, domain.ErrSessionRevoked
	}

	s.log.Info("refresh token rotated", "user_id", session.UserID, "session_id", session.ID)
	return &api.SessionResult{Session: session, SessionToken: newSessionToken, RefreshToken: newRefreshToken}, nil
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
	now := s.now().UTC()
	if now.After(session.ExpiresAt) {
		return domain.ErrSessionExpired
	}
	if s.config.IdleTTL > 0 && !now.Before(session.LastActiveAt.Add(s.config.IdleTTL)) {
		return domain.ErrSessionExpired
	}
	if s.config.MaxLifetime > 0 && !now.Before(session.CreatedAt.Add(s.config.MaxLifetime)) {
		return domain.ErrMaxLifetimeExceeded
	}
	return nil
}

// Validate validates an access token and returns its session.
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

// Touch updates a session's activity time when needed.
func (s *SessionService) Touch(ctx context.Context, token string, lastActiveAt time.Time) error {
	if s.config.TouchDebounce > 0 && time.Since(lastActiveAt) < s.config.TouchDebounce {
		return nil
	}
	return s.repo.UpdateLastActiveAt(ctx, hashToken(token))
}

// Revoke revokes a session by access token.
func (s *SessionService) Revoke(ctx context.Context, token string) error {
	if err := s.repo.Delete(ctx, hashToken(token)); err != nil {
		return fmt.Errorf("session revoke: %w", err)
	}
	return nil
}

// RevokeByID revokes a session by ID.
func (s *SessionService) RevokeByID(ctx context.Context, id string) error {
	if err := s.repo.DeleteByID(ctx, id); err != nil {
		return fmt.Errorf("session revoke by id: %w", err)
	}
	return nil
}

// RevokeByIDForUser revokes one of a user's sessions by ID.
func (s *SessionService) RevokeByIDForUser(ctx context.Context, id, userID string) (bool, error) {
	var revoked bool
	err := s.withTx(ctx, func(txCtx context.Context) error {
		ok, err := s.repo.RevokeByIDForUser(txCtx, id, userID)
		if err != nil {
			return fmt.Errorf("session revoke by id: %w", err)
		}
		revoked = ok
		if !revoked || s.audit == nil {
			return nil
		}
		// Only publish when the session actually belonged to the caller:
		// a failed cross-user revoke is a no-op, not a security event, and
		// auditing it would let a caller flood the log with probes.
		return s.audit.Record(txCtx, audit.NewSessionEvent(audit.EventSessionRevoked, userID, id, nil, ""))
	})
	if err != nil {
		return false, err
	}
	return revoked, nil
}

// RevokeManyForUser revokes multiple sessions for a user.
func (s *SessionService) RevokeManyForUser(ctx context.Context, ids []string, userID string) (int, error) {
	var revoked int
	err := s.withTx(ctx, func(txCtx context.Context) error {
		n, err := s.repo.RevokeManyForUser(txCtx, ids, userID)
		if err != nil {
			return fmt.Errorf("session revoke many: %w", err)
		}
		revoked = n
		if revoked == 0 || s.audit == nil {
			return nil
		}
		// One event for the batch, with the revoked count in metadata —
		// mirroring session.revoked_all, which also publishes a single
		// event for an unbounded set of sessions.
		return s.audit.Record(txCtx, audit.NewEvent(audit.EventSessionRevoked,
			audit.WithActor(userID), audit.WithMetadata("sessionCount", revoked)))
	})
	if err != nil {
		return 0, err
	}
	return revoked, nil
}

// RevokeAll revokes every session for a user.
func (s *SessionService) RevokeAll(ctx context.Context, userID string) error {
	return s.withTx(ctx, func(txCtx context.Context) error {
		if err := s.repo.DeleteAllForUser(txCtx, userID); err != nil {
			return fmt.Errorf("session revoke all: %w", err)
		}
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewSessionEvent(audit.EventSessionRevokedAll, userID, "", nil, "")); err != nil {
				return err
			}
		}
		return nil
	})
}

// RevokeAllExcept revokes every user session except one.
func (s *SessionService) RevokeAllExcept(ctx context.Context, userID string, exceptSessionID string) error {
	if err := s.repo.DeleteAllForUserExcept(ctx, userID, exceptSessionID); err != nil {
		return fmt.Errorf("session revoke all except: %w", err)
	}
	return nil
}

// List returns a page of sessions for a user.
func (s *SessionService) List(ctx context.Context, userID string, offset, limit int) ([]domain.Session, int, error) {
	return s.repo.ListByUserID(ctx, userID, offset, limit)
}

// ListAll returns all active sessions for a user.
func (s *SessionService) ListAll(ctx context.Context, userID string) ([]domain.Session, error) {
	return s.repo.ListAllByUserID(ctx, userID)
}

// IsSessionError reports whether an error is a session lookup failure.
func IsSessionError(err error) bool {
	return errors.Is(err, domain.ErrSessionNotFound) || errors.Is(err, domain.ErrSessionExpired)
}
