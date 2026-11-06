package sqlstore

import (
	"context"
	"database/sql"
	"strings"

	"github.com/nazimdjebloun/go-auth/domain"
)

type tokenSnapshot struct {
	Token            domain.VerificationToken `json:"token"`
	Hash             string                   `json:"hash"`
	ContextHash      string                   `json:"contextHash"`
	EncryptedPayload string                   `json:"encryptedPayload"`
	Verifier         *string                  `json:"verifier"`
	Attempts         int                      `json:"attempts"`
	Resends          int                      `json:"resends"`
}

// WithSnapshotCache enables version-validated nontransactional token reads.
func (r *TokenRepository) WithSnapshotCache(c *SnapshotCache) { r.snapshots = c }

func (v *tokenSnapshot) token(id string) *domain.VerificationToken {
	t := v.Token
	if t.ID != id || t.Type == "" || t.CreatedAt.IsZero() || t.ExpiresAt.IsZero() || v.Hash == "" || v.Attempts < 0 || v.Resends < 0 {
		return nil
	}
	t.TokenHash = v.Hash
	t.ContextHash = v.ContextHash
	t.EncryptedPayload = v.EncryptedPayload
	t.CodeVerifier = v.Verifier
	t.Attempts = v.Attempts
	t.ResendCount = v.Resends
	return &t
}

func (r *TokenRepository) cachedToken(ctx context.Context, query string, args ...any) (*domain.VerificationToken, error) {
	c := r.snapshots
	_, inTx := txFromContext(ctx)
	if c == nil || inTx {
		return scanToken(r.db.QueryRowContext(ctx, query, args...))
	}
	var id, version string
	locator := strings.Replace(query, tokenSelectColumns, "id, cache_version", 1)
	err := r.db.QueryRowContext(ctx, locator, args...).Scan(&id, &version)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if v, ok := readSnapshot[tokenSnapshot](ctx, c, "token", id, version); ok {
		if t := v.token(id); t != nil {
			return t, nil
		}
	}
	query = strings.Replace(query, tokenSelectColumns, tokenSelectColumns+", cache_version", 1)
	t, err := scanToken(r.db.QueryRowContext(ctx, query, args...), &version)
	if err != nil || t == nil {
		return t, err
	}
	writeSnapshot(ctx, c, "token", t.ID, version, tokenSnapshot{Token: *t, Hash: t.TokenHash, ContextHash: t.ContextHash, EncryptedPayload: t.EncryptedPayload, Verifier: t.CodeVerifier, Attempts: t.Attempts, Resends: t.ResendCount})
	return t, nil
}
