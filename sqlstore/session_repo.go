package sqlstore

import (
	"context"
	"database/sql"
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

const sessionCols = `id, user_id, token_hash, refresh_token_hash, prev_refresh_token_hash, ip_address, user_agent, is_revoked, expires_at, refresh_expires_at, refresh_rotated_at, created_at, revoked_at, last_active_at`

func scanSession(s *domain.Session, sc interface{ Scan(dest ...any) error }) error {
	return sc.Scan(
		&s.ID, &s.UserID, &s.TokenHash, &s.RefreshTokenHash, &s.PreviousRefreshHash,
		&s.IP, &s.UserAgent, &s.IsRevoked, &s.ExpiresAt, &s.RefreshExpiresAt,
		&s.RefreshRotatedAt, &s.CreatedAt, &s.RevokedAt, &s.LastActiveAt,
	)
}

func (r *SessionRepository) Create(ctx context.Context, s *domain.Session) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO sessions (`+sessionCols+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		s.ID, s.UserID, s.TokenHash, s.RefreshTokenHash, s.PreviousRefreshHash,
		s.IP, s.UserAgent, s.IsRevoked, s.ExpiresAt, s.RefreshExpiresAt,
		s.RefreshRotatedAt, s.CreatedAt, s.RevokedAt, s.LastActiveAt)
	return err
}

func (r *SessionRepository) GetByTokenHash(ctx context.Context, hash string) (*domain.Session, error) {
	s := &domain.Session{}
	err := scanSession(s, r.db.QueryRowContext(ctx, `
		SELECT `+sessionCols+` FROM sessions WHERE token_hash = $1`, hash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *SessionRepository) GetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	s := &domain.Session{}
	err := scanSession(s, r.db.QueryRowContext(ctx, `
		SELECT `+sessionCols+` FROM sessions WHERE refresh_token_hash = $1`, hash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *SessionRepository) GetByPreviousRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	s := &domain.Session{}
	err := scanSession(s, r.db.QueryRowContext(ctx, `
		SELECT `+sessionCols+` FROM sessions WHERE prev_refresh_token_hash = $1`, hash))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return s, err
}

func (r *SessionRepository) LockAndGetByRefreshHash(ctx context.Context, hash string) (*domain.Session, error) {
	query := `SELECT ` + sessionCols + ` FROM sessions WHERE refresh_token_hash = $1`
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
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+sessionCols+` FROM sessions WHERE user_id = $1 AND is_revoked = false AND expires_at > $2
		ORDER BY created_at DESC`, userID, now)
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

func (r *SessionRepository) UpdateRefreshToken(ctx context.Context, input port.UpdateRefreshInput) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE sessions SET
			token_hash = $1,
			refresh_token_hash = $2,
			prev_refresh_token_hash = $3,
			expires_at = $4,
			refresh_expires_at = $5,
			refresh_rotated_at = $6,
			last_active_at = $7
		WHERE id = $8 AND refresh_token_hash = $9`,
		input.NewTokenHash, input.NewRefreshHash, input.PreviousHash,
		input.NewExpiresAt, input.NewRefreshExpiry, input.RotatedAt, input.RotatedAt,
		input.SessionID, input.OldRefreshHash)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *SessionRepository) Revoke(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}
