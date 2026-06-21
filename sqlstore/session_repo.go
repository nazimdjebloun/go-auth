package sqlstore

import (
	"context"
	"database/sql"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

type SessionRepository struct {
	db *DB
}

func NewSessionRepository(db *DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, s *domain.Session) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, refresh_token, ip_address, user_agent, is_revoked, expires_at, created_at, revoked_at, last_active_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		s.ID, s.UserID, s.TokenHash, s.RefreshToken, s.IP, s.UserAgent,
		s.IsRevoked, s.ExpiresAt, s.CreatedAt, s.RevokedAt, s.LastActiveAt)
	return err
}

func (r *SessionRepository) GetByTokenHash(ctx context.Context, hash string) (*domain.Session, error) {
	s := &domain.Session{}
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, refresh_token, ip_address, user_agent, is_revoked, expires_at, created_at, revoked_at, last_active_at
		FROM sessions WHERE token_hash = $1`, hash).Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.RefreshToken, &s.IP, &s.UserAgent,
		&s.IsRevoked, &s.ExpiresAt, &s.CreatedAt, &s.RevokedAt, &s.LastActiveAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *SessionRepository) ListByUserID(ctx context.Context, userID string) ([]domain.Session, error) {
	now := time.Now().UTC()
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, user_id, token_hash, refresh_token, ip_address, user_agent, is_revoked, expires_at, created_at, revoked_at, last_active_at
		FROM sessions WHERE user_id = $1 AND is_revoked = false AND expires_at > $2
		ORDER BY created_at DESC`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []domain.Session
	for rows.Next() {
		var s domain.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.RefreshToken, &s.IP, &s.UserAgent,
			&s.IsRevoked, &s.ExpiresAt, &s.CreatedAt, &s.RevokedAt, &s.LastActiveAt); err != nil {
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
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (r *SessionRepository) DeleteByID(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

func (r *SessionRepository) DeleteAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

func (r *SessionRepository) DeleteAllForUserExcept(ctx context.Context, userID string, exceptSessionID string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1 AND id != $2`, userID, exceptSessionID)
	return err
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < $1`, time.Now().UTC())
	return err
}

func (r *SessionRepository) UpdateLastActiveAt(ctx context.Context, tokenHash string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET last_active_at = $1 WHERE token_hash = $2`, time.Now().UTC(), tokenHash)
	return err
}
