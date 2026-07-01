package sqlstore

import (
	"context"
	"database/sql"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

type ProviderAccountRepository struct {
	db *DB
}

func NewProviderAccountRepository(db *DB) *ProviderAccountRepository {
	return &ProviderAccountRepository{db: db}
}

func (r *ProviderAccountRepository) Create(ctx context.Context, pa *domain.ProviderAccount) error {
	var expiresAt *time.Time
	if pa.TokenExpiresAt != nil {
		expiresAt = pa.TokenExpiresAt
	}
	_, err := r.db.ExecContext(ctx, providerAccountCreateQuery,
		pa.ID, pa.UserID, pa.Provider, pa.ProviderUserID, pa.ProviderEmail, pa.ProviderName, pa.AvatarURL,
		nullIfEmpty(pa.AccessToken), nullIfEmpty(pa.RefreshToken), expiresAt, pa.CreatedAt, pa.UpdatedAt)
	return err
}

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
		pa.AccessToken = accessToken.String
	}
	if refreshToken.Valid {
		pa.RefreshToken = refreshToken.String
	}
	if tokenExpiresAt.Valid {
		pa.TokenExpiresAt = &tokenExpiresAt.Time
	}
	return pa, nil
}

func (r *ProviderAccountRepository) ListByUserID(ctx context.Context, userID string) ([]domain.ProviderAccount, error) {
	rows, err := r.db.QueryContext(ctx, providerAccountListByUserQuery, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accounts []domain.ProviderAccount
	for rows.Next() {
		var pa domain.ProviderAccount
		var accessToken, refreshToken sql.NullString
		var tokenExpiresAt sql.NullTime
		if err := rows.Scan(
			&pa.ID, &pa.UserID, &pa.Provider, &pa.ProviderUserID, &pa.ProviderEmail, &pa.ProviderName, &pa.AvatarURL,
			&accessToken, &refreshToken, &tokenExpiresAt, &pa.CreatedAt, &pa.UpdatedAt); err != nil {
			return nil, err
		}
		if accessToken.Valid {
			pa.AccessToken = accessToken.String
		}
		if refreshToken.Valid {
			pa.RefreshToken = refreshToken.String
		}
		if tokenExpiresAt.Valid {
			pa.TokenExpiresAt = &tokenExpiresAt.Time
		}
		accounts = append(accounts, pa)
	}
	if accounts == nil {
		return []domain.ProviderAccount{}, nil
	}
	return accounts, rows.Err()
}

func (r *ProviderAccountRepository) Delete(ctx context.Context, userID, provider string) error {
	_, err := r.db.ExecContext(ctx, providerAccountDeleteQuery, userID, provider)
	return err
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
