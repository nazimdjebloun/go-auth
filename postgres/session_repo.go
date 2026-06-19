package postgres

import (
	"context"
	"database/sql"

	"github.com/nazimdjebloun/go-auth/domain"
)

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, s *domain.Session) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, ip_address, user_agent, is_revoked, expires_at, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		s.ID, s.UserID, s.TokenHash, s.IPAddress, s.UserAgent, s.IsRevoked, s.ExpiresAt, s.CreatedAt, s.LastUsedAt)
	return err
}

func (r *SessionRepository) GetByTokenHash(ctx context.Context, hash string) (*domain.Session, error) {
	s := &domain.Session{}
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, ip_address, user_agent, is_revoked, expires_at, created_at, last_used_at
		FROM sessions WHERE token_hash = $1`, hash).Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.IPAddress, &s.UserAgent,
		&s.IsRevoked, &s.ExpiresAt, &s.CreatedAt, &s.LastUsedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *SessionRepository) ListByUserID(ctx context.Context, userID string) ([]domain.Session, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, user_id, token_hash, ip_address, user_agent, is_revoked, expires_at, created_at, last_used_at
		FROM sessions WHERE user_id = $1 AND is_revoked = false AND expires_at > NOW()
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []domain.Session
	for rows.Next() {
		var s domain.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.TokenHash, &s.IPAddress, &s.UserAgent,
			&s.IsRevoked, &s.ExpiresAt, &s.CreatedAt, &s.LastUsedAt); err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}
	if sessions == nil {
		sessions = []domain.Session{}
	}
	return sessions, rows.Err()
}

func (r *SessionRepository) Revoke(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET is_revoked = true WHERE id = $1`, id)
	return err
}

func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sessions SET is_revoked = true WHERE user_id = $1 AND is_revoked = false`, userID)
	return err
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < NOW()`)
	return err
}
