package port

import (
	"context"
	"github.com/nazimdjebloun/go-auth/domain"
	"time"
)

// ConsumeTokenInput identifies one exact, still-valid token row. Repositories
// must apply every predicate in the same UPDATE that stamps UsedAt so two
// callers cannot both consume the token after racing through an earlier read.
type ConsumeTokenInput struct {
	ID        string
	TokenHash string
	UserID    string
	Type      domain.TokenType
	UsedAt    time.Time
}

// TokenRepository stores workflow verification tokens.
type TokenRepository interface {
	Create(ctx context.Context, t *domain.VerificationToken) error
	GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error)
	GetByID(ctx context.Context, id string) (*domain.VerificationToken, error)
	GetLastByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) (*domain.VerificationToken, error)
	HasValidByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) (bool, error)
	MarkUsed(ctx context.Context, id string) error
	// MarkUsedIfUnused atomically claims an unused token. It returns false
	// when the token is missing or another caller already claimed it.
	MarkUsedIfUnused(ctx context.Context, id string) (bool, error)
	ConsumeIfValid(ctx context.Context, input ConsumeTokenInput) (bool, error)
	// ConsumeIfValidUnderCap applies the exact token identity, unused state,
	// expiry at UsedAt, and attempt cap in one update. Use for 2FA so a resend
	// cannot authorize a claim using a previously compared code.
	ConsumeIfValidUnderCap(ctx context.Context, input ConsumeTokenInput, maxAttempts int) (bool, error)
	DeleteExpired(ctx context.Context) error
	// DeleteUnusedByID removes only the named unused token. Delivery cleanup
	// must not remove codes another request successfully issued.
	DeleteUnusedByID(ctx context.Context, id string) error
	DeleteUnusedByUserAndType(ctx context.Context, userID string, tokenType domain.TokenType) error

	// IncrementAttempts, MarkUsedIfUnderCap and UpdateForResend are guarded
	// updates: each applies its cap in the WHERE clause and reports whether the
	// row was actually touched. Read-then-write would be a TOCTOU — concurrent
	// requests all observe the same pre-increment count and all pass the cap
	// check before any write lands. Returning bool rather than the new count
	// also keeps them driver-portable: MySQL has no UPDATE...RETURNING.
	IncrementAttempts(ctx context.Context, id string, maxAttemptsPerChallenge int) (bool, error)
	MarkUsedIfUnderCap(ctx context.Context, id string, maxAttemptsPerChallenge int) (bool, error)
	// UpdateForResend refreshes the code on a challenge row: new hash, new
	// expiry, and a refreshed created_at — the row now represents a newly
	// issued code, so created_at must track the newest issuance, not the
	// lineage's birth. In particular a resend after an OTP-pepper rotation
	// has to lift the row out of rotation-stale (see service.stalePepper),
	// or the fresh code would still compare as predating the live pepper.
	UpdateForResend(ctx context.Context, id string, newHash string, newExpiresAt time.Time, newCreatedAt time.Time, maxRefreshesPerChallenge, maxAttemptsPerChallenge int) (bool, error)
}
