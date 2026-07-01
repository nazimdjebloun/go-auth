package sqlstore

import (
	"context"
	"database/sql"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

type TokenRepository struct {
	db *DB
}

func NewTokenRepository(db *DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) Create(ctx context.Context, t *domain.VerificationToken) error {
	_, err := r.db.ExecContext(ctx, tokenCreateQuery,
		t.ID, t.UserID, t.Email, t.TokenHash, t.Type, t.ExpiresAt, t.UsedAt)
	return err
}

func (r *TokenRepository) GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error) {
	t := &domain.VerificationToken{}
	var userID sql.NullString
	var usedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, tokenByHashQuery, hash).Scan(
		&t.ID, &userID, &t.Email, &t.TokenHash, &t.Type, &t.ExpiresAt, &usedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if userID.Valid {
		t.UserID = &userID.String
	}
	if usedAt.Valid {
		t.UsedAt = &usedAt.Time
	}
	return t, nil
}

func (r *TokenRepository) MarkUsed(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, tokenMarkUsedQuery, time.Now().UTC(), id)
	return err
}

func (r *TokenRepository) DeleteExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, tokenDeleteExpiredQuery, time.Now().UTC())
	return err
}

func (r *TokenRepository) DeleteUnusedByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) error {
	_, err := r.db.ExecContext(ctx, tokenDeleteUnusedByUserAndTypeQuery, userID, tokenType)
	return err
}
