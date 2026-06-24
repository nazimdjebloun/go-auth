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
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO verification_tokens (id, user_id, email, token_hash, type, expires_at, used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		t.ID, t.UserID, t.Email, t.TokenHash, t.Type, t.ExpiresAt, t.UsedAt)
	return err
}

func (r *TokenRepository) GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error) {
	t := &domain.VerificationToken{}
	var userID sql.NullString
	var usedAt sql.NullTime
	err := r.db.QueryRowContext(ctx, `
		SELECT id, user_id, email, token_hash, type, expires_at, used_at
		FROM verification_tokens WHERE token_hash = $1`, hash).Scan(
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
	_, err := r.db.ExecContext(ctx, `UPDATE verification_tokens SET used_at = $1 WHERE id = $2 AND used_at IS NULL`, time.Now().UTC(), id)
	return err
}

func (r *TokenRepository) DeleteExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM verification_tokens WHERE expires_at < $1`, time.Now().UTC())
	return err
}

func (r *TokenRepository) DeleteUnusedByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) error {
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM verification_tokens WHERE user_id=$1 AND type=$2 AND used_at IS NULL`,
		userID, tokenType)
	return err
}
