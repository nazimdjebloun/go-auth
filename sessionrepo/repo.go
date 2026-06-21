package sessionrepo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type SessionRepository struct {
	pool *pgxpool.Pool
	db   *sql.DB
}

func New(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{pool: pool}
}

func NewFromDB(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

var _ port.SessionRepository = (*SessionRepository)(nil)

func (r *SessionRepository) Create(ctx context.Context, s *domain.Session) error {
	query := `
		INSERT INTO sessions (id, user_id, token_hash, refresh_token, ip_address, user_agent, is_revoked, expires_at, created_at, revoked_at, last_active_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	if r.pool != nil {
		_, err := r.pool.Exec(ctx, query, s.ID, s.UserID, s.TokenHash, s.RefreshToken, s.IP, s.UserAgent, s.IsRevoked, s.ExpiresAt, s.CreatedAt, s.RevokedAt, s.LastActiveAt)
		if err != nil {
			return fmt.Errorf("session create: %w", err)
		}
		return nil
	}
	_, err := r.db.ExecContext(ctx, query, s.ID, s.UserID, s.TokenHash, s.RefreshToken, s.IP, s.UserAgent, s.IsRevoked, s.ExpiresAt, s.CreatedAt, s.RevokedAt, s.LastActiveAt)
	if err != nil {
		return fmt.Errorf("session create: %w", err)
	}
	return nil
}

func scanSession(id, userID, tokenHash, refreshToken, ip, userAgent string, isRevoked bool, expiresAt, createdAt time.Time, revokedAt *time.Time, lastActiveAt time.Time) *domain.Session {
	return &domain.Session{
		ID:           id,
		UserID:       userID,
		TokenHash:    tokenHash,
		RefreshToken: refreshToken,
		IP:           ip,
		UserAgent:    userAgent,
		IsRevoked:    isRevoked,
		ExpiresAt:    expiresAt,
		CreatedAt:    createdAt,
		RevokedAt:    revokedAt,
		LastActiveAt: lastActiveAt,
	}
}

const sessionColumns = "id, user_id, token_hash, refresh_token, ip_address, user_agent, is_revoked, expires_at, created_at, revoked_at, last_active_at"
const sessionSelect = "SELECT " + sessionColumns + " FROM sessions"

func (r *SessionRepository) GetByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error) {
	if r.pool != nil {
		s, err := r.scanRow(r.pool.QueryRow(ctx, sessionSelect+" WHERE token_hash = $1", tokenHash))
		if err != nil {
			return nil, err
		}
		return s, nil
	}
	row := r.db.QueryRowContext(ctx, sessionSelect+" WHERE token_hash = $1", tokenHash)
	return r.scanRowDB(row)
}

func (r *SessionRepository) ListByUserID(ctx context.Context, userID string) ([]domain.Session, error) {
	query := sessionSelect + " WHERE user_id = $1 AND expires_at > $2 ORDER BY created_at DESC"
	now := time.Now().UTC()
	if r.pool != nil {
		rows, err := r.pool.Query(ctx, query, userID, now)
		if err != nil {
			return nil, fmt.Errorf("session list: %w", err)
		}
		defer rows.Close()
		return r.scanRows(rows)
	}
	rows, err := r.db.QueryContext(ctx, query, userID, now)
	if err != nil {
		return nil, fmt.Errorf("session list: %w", err)
	}
	defer rows.Close()
	return r.scanRowsDB(rows)
}

func (r *SessionRepository) Delete(ctx context.Context, tokenHash string) error {
	return r.exec(ctx, "DELETE FROM sessions WHERE token_hash = $1", tokenHash)
}

func (r *SessionRepository) DeleteByID(ctx context.Context, id string) error {
	return r.exec(ctx, "DELETE FROM sessions WHERE id = $1", id)
}

func (r *SessionRepository) DeleteAllForUser(ctx context.Context, userID string) error {
	return r.exec(ctx, "DELETE FROM sessions WHERE user_id = $1", userID)
}

func (r *SessionRepository) DeleteAllForUserExcept(ctx context.Context, userID string, exceptSessionID string) error {
	return r.exec(ctx, "DELETE FROM sessions WHERE user_id = $1 AND id != $2", userID, exceptSessionID)
}

func (r *SessionRepository) DeleteExpired(ctx context.Context) error {
	return r.exec(ctx, "DELETE FROM sessions WHERE expires_at < $1", time.Now().UTC())
}

func (r *SessionRepository) UpdateLastActiveAt(ctx context.Context, tokenHash string) error {
	return r.exec(ctx, "UPDATE sessions SET last_active_at = $1 WHERE token_hash = $2", time.Now().UTC(), tokenHash)
}

func (r *SessionRepository) exec(ctx context.Context, query string, args ...any) error {
	var err error
	if r.pool != nil {
		_, err = r.pool.Exec(ctx, query, args...)
	} else {
		_, err = r.db.ExecContext(ctx, query, args...)
	}
	if err != nil {
		return fmt.Errorf("session exec: %w", err)
	}
	return nil
}

func (r *SessionRepository) scanRow(row pgx.Row) (*domain.Session, error) {
	var id, userID, tokenHash, refreshToken, ip, userAgent string
	var isRevoked bool
	var expiresAt, createdAt time.Time
	var revokedAt *time.Time
	var lastActiveAt time.Time
	err := row.Scan(&id, &userID, &tokenHash, &refreshToken, &ip, &userAgent, &isRevoked, &expiresAt, &createdAt, &revokedAt, &lastActiveAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("session scan: %w", err)
	}
	return scanSession(id, userID, tokenHash, refreshToken, ip, userAgent, isRevoked, expiresAt, createdAt, revokedAt, lastActiveAt), nil
}

func (r *SessionRepository) scanRowDB(row *sql.Row) (*domain.Session, error) {
	var id, userID, tokenHash, refreshToken, ip, userAgent string
	var isRevoked bool
	var expiresAt, createdAt time.Time
	var revokedAt *time.Time
	var lastActiveAt time.Time
	err := row.Scan(&id, &userID, &tokenHash, &refreshToken, &ip, &userAgent, &isRevoked, &expiresAt, &createdAt, &revokedAt, &lastActiveAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("session scan: %w", err)
	}
	return scanSession(id, userID, tokenHash, refreshToken, ip, userAgent, isRevoked, expiresAt, createdAt, revokedAt, lastActiveAt), nil
}

func (r *SessionRepository) scanRows(rows pgx.Rows) ([]domain.Session, error) {
	var sessions []domain.Session
	for rows.Next() {
		var id, userID, tokenHash, refreshToken, ip, userAgent string
		var isRevoked bool
		var expiresAt, createdAt time.Time
		var revokedAt *time.Time
		var lastActiveAt time.Time
		if err := rows.Scan(&id, &userID, &tokenHash, &refreshToken, &ip, &userAgent, &isRevoked, &expiresAt, &createdAt, &revokedAt, &lastActiveAt); err != nil {
			return nil, fmt.Errorf("session scan: %w", err)
		}
		sessions = append(sessions, *scanSession(id, userID, tokenHash, refreshToken, ip, userAgent, isRevoked, expiresAt, createdAt, revokedAt, lastActiveAt))
	}
	if sessions == nil {
		sessions = []domain.Session{}
	}
	return sessions, rows.Err()
}

func (r *SessionRepository) scanRowsDB(rows *sql.Rows) ([]domain.Session, error) {
	var sessions []domain.Session
	for rows.Next() {
		var id, userID, tokenHash, refreshToken, ip, userAgent string
		var isRevoked bool
		var expiresAt, createdAt time.Time
		var revokedAt *time.Time
		var lastActiveAt time.Time
		if err := rows.Scan(&id, &userID, &tokenHash, &refreshToken, &ip, &userAgent, &isRevoked, &expiresAt, &createdAt, &revokedAt, &lastActiveAt); err != nil {
			return nil, fmt.Errorf("session scan: %w", err)
		}
		sessions = append(sessions, *scanSession(id, userID, tokenHash, refreshToken, ip, userAgent, isRevoked, expiresAt, createdAt, revokedAt, lastActiveAt))
	}
	if sessions == nil {
		sessions = []domain.Session{}
	}
	return sessions, rows.Err()
}
