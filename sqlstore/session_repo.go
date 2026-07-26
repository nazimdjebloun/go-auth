package sqlstore

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type SessionRepository struct {
	db *DB
}

func NewSessionRepository(db *DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func scanSession(s *domain.Session, sc interface{ Scan(dest ...any) error }) error {
	return sc.Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.RefreshTokenHash, &s.PreviousRefreshHash,
		&s.IP, &s.UserAgent, &s.IsRevoked, &s.ExpiresAt, &s.RefreshExpiresAt,
		&s.RefreshRotatedAt, &s.CreatedAt, &s.RevokedAt, &s.LastActiveAt,
	)
}

func (r *SessionRepository) Create(ctx context.Context, s *domain.Session) error {
	_, err := r.db.ExecContext(ctx, sessionCreateQuery,
		s.ID, s.UserID, s.TokenHash, s.RefreshTokenHash, s.PreviousRefreshHash,
		s.IP, s.UserAgent, s.IsRevoked, s.ExpiresAt, s.RefreshExpiresAt,
		s.RefreshRotatedAt, s.CreatedAt, s.RevokedAt, s.LastActiveAt)
	return err
}

func (r *SessionRepository) GetByTokenHash(ctx context.Context, hash string) (*domain.Session, error) {
	s := &domain.Session{}
	err := scanSession(s, r.db.QueryRowContext(ctx, sessionByTokenHashQuery, hash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *SessionRepository) GetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	s := &domain.Session{}
	err := scanSession(s, r.db.QueryRowContext(ctx, sessionByRefreshHashQuery, hash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *SessionRepository) GetByPreviousRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	s := &domain.Session{}
	err := scanSession(s, r.db.QueryRowContext(ctx, sessionByPreviousRefreshHashQuery, hash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *SessionRepository) LockAndGetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	query := sessionByRefreshHashQuery
	if r.db.Driver() == "postgres" {
		query += " FOR UPDATE"
	}
	s := &domain.Session{}
	err := scanSession(s, r.db.QueryRowContext(ctx, query, hash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *SessionRepository) ListByUserID(ctx context.Context, userID string) ([]domain.Session, error) {
	now := time.Now().UTC()
	rows, err := r.db.QueryContext(ctx, sessionListByUserQuery, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []domain.Session
	for rows.Next() {
		var s domain.Session
		if err := scanSession(&s, rows); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	if sessions == nil {
		sessions = []domain.Session{}
	}
	return sessions, rows.Err()
}

func (r *SessionRepository) Delete(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, sessionDeleteByTokenHashQuery, tokenHash)
	return err
}

func (r *SessionRepository) DeleteByID(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, sessionDeleteByIDQuery, id)
	return err
}

func (r *SessionRepository) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, sessionDeleteByUserQuery, userID)
	return err
}

func (r *SessionRepository) DeleteAllForUserExcept(ctx context.Context, userID string, exceptSessionID string) error {
	_, err := r.db.ExecContext(ctx, sessionDeleteByUserExceptQuery, userID, exceptSessionID)
	return err
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, sessionDeleteExpiredQuery, time.Now().UTC())
	return err
}

func (r *SessionRepository) UpdateLastActiveAt(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, sessionUpdateLastActiveQuery, time.Now().UTC(), tokenHash)
	return err
}

// ---------------------------------------------------------------------------
// Refresh token rotation
// ---------------------------------------------------------------------------

func (r *SessionRepository) UpdateRefreshToken(ctx context.Context, input port.UpdateRefreshInput) (*domain.Session, error) {
	now := input.RotatedAt

	// Collision guard: reject degenerate inputs that would cause silent
	// no-ops (NewRefreshHash == OldRefreshHash makes UPDATE match on
	// the new hash, so rotation writes the same hash back) or token-type
	// confusion (NewRefreshHash == NewTokenHash).
	if input.NewRefreshHash == input.OldRefreshHash {
		return nil, domain.NewError("internal_error",
			"Refresh token collision: new hash equals old hash", http.StatusInternalServerError)
	}
	if input.NewRefreshHash == input.NewTokenHash {
		return nil, domain.NewError("internal_error",
			"Token hash collision: refresh hash equals access token hash", http.StatusInternalServerError)
	}

	var maxLifetimeCut time.Time
	if input.MaxLifetime > 0 {
		maxLifetimeCut = now.Add(-input.MaxLifetime)
	} else {
		maxLifetimeCut = time.Unix(0, 0)
	}

	if r.db.Driver() == "mysql" {
		return r.updateRefreshTokenNoReturning(ctx, input, now, maxLifetimeCut)
	}

	return r.updateRefreshTokenReturning(ctx, input, now, maxLifetimeCut)
}

// updateRefreshTokenReturning uses a single atomic UPDATE...RETURNING
// (PostgreSQL, SQLite).
func (r *SessionRepository) updateRefreshTokenReturning(ctx context.Context, input port.UpdateRefreshInput, now, maxLifetimeCut time.Time) (*domain.Session, error) {
	// CRITICAL SQLite note: modernc.org/sqlite omits rows from
	// UPDATE...RETURNING when SET values equal existing values (even if
	// WHERE matched). This is safe here because we always set
	// refresh_token_hash to a freshly generated value (never the same
	// as the current one, enforced by the collision guard above).
	session := &domain.Session{}
	err := scanSession(session, r.db.QueryRowContext(ctx, sessionRotateRefreshQuery,
		input.NewTokenHash, input.NewRefreshHash, now, input.NewExpiresAt,
		input.OldRefreshHash, now, maxLifetimeCut))
	if err == nil {
		return session, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	return r.classifyRefreshFailure(ctx, input, now, maxLifetimeCut)
}

// updateRefreshTokenNoReturning uses ExecContext + RowsAffected (MySQL).
func (r *SessionRepository) updateRefreshTokenNoReturning(ctx context.Context, input port.UpdateRefreshInput, now, maxLifetimeCut time.Time) (*domain.Session, error) {
	query := r.db.Rebind(`UPDATE sessions
		SET token_hash = ?, refresh_token_hash = ?,
		    prev_refresh_token_hash = refresh_token_hash,
		    refresh_rotated_at = ?, expires_at = ?
		WHERE refresh_token_hash = ? AND is_revoked = false
		  AND refresh_expires_at > ? AND created_at > ?`)

	result, err := r.db.ExecContext(ctx, query,
		input.NewTokenHash, input.NewRefreshHash, now, input.NewExpiresAt,
		input.OldRefreshHash, now, maxLifetimeCut)
	if err != nil {
		return nil, err
	}
	rows, _ := result.RowsAffected()
	if rows == 1 {
		// Non-atomic read-back, but safe: NewRefreshHash is freshly
		// generated and unguessable, so no concurrent request can be
		// operating on it. Unlike Postgres/SQLite's single-statement
		// RETURNING, this is a separate SELECT after the UPDATE. If
		// the read fails, the rotation succeeded in the DB but the
		// caller receives an error — the token is still valid and
		// the caller should retry.
		return r.GetByRefreshHash(ctx, input.NewRefreshHash)
	}
	return r.classifyRefreshFailure(ctx, input, now, maxLifetimeCut)
}

func (r *SessionRepository) classifyRefreshFailure(ctx context.Context, input port.UpdateRefreshInput, now time.Time, maxLifetimeCut time.Time) (*domain.Session, error) {
	session, err := r.GetByRefreshHash(ctx, input.OldRefreshHash)
	if err != nil {
		return nil, err
	}

	if session != nil {
		if session.IsRevoked {
			return nil, domain.ErrSessionRevoked
		}
		if now.After(session.RefreshExpiresAt) {
			return nil, domain.ErrRefreshExpired
		}
		if input.MaxLifetime > 0 && now.After(session.CreatedAt.Add(input.MaxLifetime)) {
			return nil, domain.ErrMaxLifetimeExceeded
		}

		// INVARIANT VIOLATION: old hash is still current, no WHERE
		// guard rejects it, yet UPDATE...RETURNING returned 0 rows.
		// Under correct transaction isolation this is unreachable.
		// Likely causes: broken isolation, clock skew, or a bypassed
		// write path. Log at ERROR, return 500 — NOT a routine 409.
		log.Printf("ERROR: refresh rotation invariant violation — UPDATE returned 0 rows but all WHERE guards pass: session_id=%s user_id=%s is_revoked=%v refresh_expires_at=%v created_at=%v now=%v max_lifetime_cut=%v",
			session.ID, session.UserID,
			session.IsRevoked, session.RefreshExpiresAt, session.CreatedAt, now, maxLifetimeCut)
		return nil, domain.NewError("internal_error",
			"Session rotation failed due to internal state conflict", http.StatusInternalServerError)
	}

	// Old hash not current — check previous hash
	prev, err := r.GetByPreviousRefreshHash(ctx, input.OldRefreshHash)
	if err != nil {
		return nil, err
	}

	if prev != nil {
		if prev.RefreshRotatedAt != nil && now.Sub(*prev.RefreshRotatedAt) < input.GraceWindow {
			log.Printf("WARN: refresh_token_reuse_in_grace_window user_id=%s session_id=%s",
				prev.UserID, prev.ID)
			return nil, domain.ErrTokenAlreadyRotated
		}

		log.Printf("WARN: refresh_token_reuse_theft_suspected user_id=%s session_id=%s",
			prev.UserID, prev.ID)
		if revokeErr := r.Revoke(ctx, prev.ID); revokeErr != nil {
			log.Printf("ERROR: failed to revoke session on reuse detection: %v", revokeErr)
		}
		return nil, domain.ErrSessionRevoked
	}

	return nil, domain.ErrInvalidRefreshToken
}

func (r *SessionRepository) Revoke(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, sessionDeleteByIDQuery, id)
	return err
}
