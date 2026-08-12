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
	// Callers construct tokens without a CreatedAt; fill it here rather than
	// relying on the column default, so GetLastByUserAndType's ORDER BY sees a
	// value the application controls and every driver agrees on.
	createdAt := t.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	_, err := r.db.ExecContext(ctx, tokenCreateQuery,
		t.ID, t.UserID, t.Email, t.TokenHash, t.Type, t.ExpiresAt, t.UsedAt, t.CodeVerifier,
		t.Attempts, t.ResendCount, createdAt)
	return err
}

// scanToken reads the tokenSelectColumns list, in that order, into a token.
// Returns (nil, nil) when the row is absent, matching the repository's
// existing "missing is not an error" convention.
func scanToken(s scanner) (*domain.VerificationToken, error) {
	t := &domain.VerificationToken{}
	var userID sql.NullString
	var usedAt sql.NullTime
	var codeVerifier sql.NullString
	err := s.Scan(
		&t.ID, &userID, &t.Email, &t.TokenHash, &t.Type, &t.ExpiresAt, &usedAt,
		&t.CreatedAt, &codeVerifier, &t.Attempts, &t.ResendCount)
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
	if codeVerifier.Valid {
		t.CodeVerifier = &codeVerifier.String
	}
	return t, nil
}

func (r *TokenRepository) GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error) {
	return scanToken(r.db.QueryRowContext(ctx, tokenByHashQuery, hash))
}

func (r *TokenRepository) GetByID(ctx context.Context, id string) (*domain.VerificationToken, error) {
	return scanToken(r.db.QueryRowContext(ctx, tokenByIDQuery, id))
}

func (r *TokenRepository) GetLastByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) (*domain.VerificationToken, error) {
	return scanToken(r.db.QueryRowContext(ctx, tokenGetLastByUserAndTypeQuery, userID, tokenType))
}

func (r *TokenRepository) MarkUsed(ctx context.Context, id string) error {
	_, err := r.db.ExecContext(ctx, tokenMarkUsedQuery, time.Now().UTC(), id)
	return err
}

func (r *TokenRepository) HasValidByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) (bool, error) {
	var exists bool
	err := r.db.QueryRowContext(ctx, tokenHasValidByUserAndTypeQuery, userID, tokenType, time.Now().UTC()).Scan(&exists)
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (r *TokenRepository) DeleteExpired(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, tokenDeleteExpiredQuery, time.Now().UTC())
	return err
}

func (r *TokenRepository) DeleteUnusedByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) error {
	_, err := r.db.ExecContext(ctx, tokenDeleteUnusedByUserAndTypeQuery, userID, tokenType)
	return err
}

// affected reports whether a guarded UPDATE actually touched its row. Every
// one of these statements changes a column value when it matches, so MySQL's
// changed-rows accounting agrees with matched-rows here.
func affected(res sql.Result, err error) (bool, error) {
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

func (r *TokenRepository) IncrementAttempts(ctx context.Context, id string, maxAttemptsPerChallenge int) (bool, error) {
	return affected(r.db.ExecContext(ctx, tokenIncrementAttemptsQuery, id, maxAttemptsPerChallenge))
}

func (r *TokenRepository) MarkUsedIfUnderCap(ctx context.Context, id string, maxAttemptsPerChallenge int) (bool, error) {
	return affected(r.db.ExecContext(ctx, tokenMarkUsedIfUnderCapQuery, time.Now().UTC(), id, maxAttemptsPerChallenge))
}

func (r *TokenRepository) UpdateForResend(ctx context.Context, id string, newHash string, newExpiresAt time.Time, maxRefreshesPerChallenge, maxAttemptsPerChallenge int) (bool, error) {
	return affected(r.db.ExecContext(ctx, tokenUpdateForResendQuery,
		newHash, newExpiresAt, id, maxRefreshesPerChallenge, maxAttemptsPerChallenge))
}
