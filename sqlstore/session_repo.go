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

func (r *SessionRepository) UpdateRefreshToken(ctx context.Context, input port.UpdateRefreshInput) (int64, error) {
	res, err := r.db.ExecContext(ctx, sessionUpdateRefreshQuery,
		input.NewTokenHash, input.NewRefreshHash, input.PreviousHash,
		input.NewExpiresAt, input.NewRefreshExpiry, input.RotatedAt, input.RotatedAt,
		input.SessionID, input.OldRefreshHash)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (r *SessionRepository) Revoke(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, sessionDeleteByIDQuery, id)
	return err
}
