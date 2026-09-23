package sqlstore

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// ProviderAccountRepository stores external provider accounts.
type ProviderAccountRepository struct {
	db           *DB
	decryptToken func(string) (string, error)
}

// NewProviderAccountRepository returns a provider account repository.
func NewProviderAccountRepository(db *DB) *ProviderAccountRepository {
	return &ProviderAccountRepository{db: db}
}

// WithDecryptor sets the provider token decryptor.
func (r *ProviderAccountRepository) WithDecryptor(decrypt func(string) (string, error)) {
	r.decryptToken = decrypt
}

// Create stores a provider account.
func (r *ProviderAccountRepository) Create(ctx context.Context, pa *domain.ProviderAccount) error {
	var expiresAt *time.Time
	if pa.TokenExpiresAt != nil {
		expiresAt = pa.TokenExpiresAt
	}
	_, err := r.db.ExecContext(ctx, providerAccountCreateQuery,
		pa.ID, pa.UserID, pa.Provider, pa.ProviderUserID, pa.ProviderEmail, pa.ProviderName, pa.AvatarURL,
		nullIfEmpty(pa.AccessToken), nullIfEmpty(pa.RefreshToken), expiresAt, pa.CreatedAt, pa.UpdatedAt)
	return wrapCreateErr(r.db.Driver(), err)
}

// GetByProvider returns an account by provider identity or nil when absent.
func (r *ProviderAccountRepository) GetByProvider(ctx context.Context, provider, providerUserID string) (*domain.ProviderAccount, error) {
	pa := &domain.ProviderAccount{}
	var accessToken, refreshToken sql.NullString
	var tokenExpiresAt sql.NullTime
	err := r.db.QueryRowContext(ctx, providerAccountByProviderQuery, provider, providerUserID).Scan(
		&pa.ID, &pa.UserID, &pa.Provider, &pa.ProviderUserID, &pa.ProviderEmail, &pa.ProviderName, &pa.AvatarURL,
		&accessToken, &refreshToken, &tokenExpiresAt, &pa.CreatedAt, &pa.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if accessToken.Valid {
		pa.AccessToken = r.decrypt(accessToken.String)
	}
	if refreshToken.Valid {
		pa.RefreshToken = r.decrypt(refreshToken.String)
	}
	if tokenExpiresAt.Valid {
		pa.TokenExpiresAt = &tokenExpiresAt.Time
	}
	return pa, nil
}

// ListByUserID returns the provider accounts linked to a user.
func (r *ProviderAccountRepository) ListByUserID(ctx context.Context, userID string) ([]domain.ProviderAccount, error) {
	rows, err := r.db.QueryContext(ctx, providerAccountListByUserQuery, userID)
	if err != nil {
		return nil, err
	}

	var accounts []domain.ProviderAccount
	for rows.Next() {
		var pa domain.ProviderAccount
		var accessToken, refreshToken sql.NullString
		var tokenExpiresAt sql.NullTime
		if err := rows.Scan(
			&pa.ID, &pa.UserID, &pa.Provider, &pa.ProviderUserID, &pa.ProviderEmail, &pa.ProviderName, &pa.AvatarURL,
			&accessToken, &refreshToken, &tokenExpiresAt, &pa.CreatedAt, &pa.UpdatedAt); err != nil {
			_ = rows.Close()
			return nil, err
		}
		if accessToken.Valid {
			pa.AccessToken = r.decrypt(accessToken.String)
		}
		if refreshToken.Valid {
			pa.RefreshToken = r.decrypt(refreshToken.String)
		}
		if tokenExpiresAt.Valid {
			pa.TokenExpiresAt = &tokenExpiresAt.Time
		}
		accounts = append(accounts, pa)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("provider account list close: %w", err)
	}
	if accounts == nil {
		return []domain.ProviderAccount{}, nil
	}
	return accounts, nil
}

func (r *ProviderAccountRepository) decrypt(s string) string {
	if r.decryptToken == nil || s == "" {
		return s
	}
	dec, err := r.decryptToken(s)
	if err != nil {
		return s
	}
	return dec
}

// Delete removes a provider account link.
func (r *ProviderAccountRepository) Delete(ctx context.Context, userID, provider string) error {
	_, err := r.db.ExecContext(ctx, providerAccountDeleteQuery, userID, provider)
	return err
}

// LockByUserID locks and returns a user's provider accounts.
func (r *ProviderAccountRepository) LockByUserID(ctx context.Context, userID string) error {
	_, err := r.db.ExecContext(ctx, providerAccountLockByUserQuery, userID)
	return err
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
