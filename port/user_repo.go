package port

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// UserFilter narrows and orders user queries.
type UserFilter struct {
	// IDs matches any of the listed user IDs ("IN (...)") — a batch lookup,
	// not a per-admin-question filter like the fields below it. Used to
	// resolve a page of IDs (e.g. audit log actor/target IDs) to users in
	// one round trip instead of one query per ID.
	IDs              []string
	Email            *string
	Role             *domain.Role
	IsBanned         *bool
	IsVerified       *bool
	TwoFactorEnabled *bool
	// NeverLoggedIn and LastLoginBefore are independent, composable dormancy
	// filters, not one merged "inactive since" flag: "registered, never
	// logged in since" and "logged in before, gone dormant since" are
	// different admin questions.
	NeverLoggedIn   *bool      // true: last_login_at IS NULL
	LastLoginBefore *time.Time // last_login_at < X, excluding NULLs
	// CreatedAfter/CreatedBefore scope List/CountByDay to a registration
	// date range — used by the admin registrations-over-time trend.
	CreatedAfter   *time.Time
	CreatedBefore  *time.Time
	Search         *string
	OrderBy        api.UserSortField
	OrderDirection api.SortDirection
	Offset         int
	Limit          int // 0 means unlimited
}

// PasswordHashUpdater performs the narrow, guarded credential write used by
// login rehash, password change, and password reset. Implementations update
// only when both oldHash and oldPepperVersion are still stored and must reject
// a newPepperVersion lower than oldPepperVersion. False means a concurrent
// password write won the race or the requested write would be a downgrade.
type PasswordHashUpdater interface {
	UpdatePasswordHash(ctx context.Context, userID, oldHash string, oldPepperVersion *uint32, newHash string, newPepperVersion *uint32, updatedAt time.Time) (bool, error)
}

// UserRepository stores user accounts and credentials.
type UserRepository interface {
	PasswordHashUpdater
	AdminGuardStore
	// UpdateName changes only name and updated_at. False means the user
	// no longer exists.
	UpdateName(ctx context.Context, userID, name string, updatedAt time.Time) (bool, error)
	// VerifyEmailIfMatches sets only verification fields and updated_at,
	// provided the stored email still exactly matches expectedEmail. False
	// means the user is absent or the email changed. Implementations must
	// honor transaction contexts.
	VerifyEmailIfMatches(ctx context.Context, userID, expectedEmail string, verifiedAt time.Time) (bool, error)
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	// Update persists user metadata only. It must not replace PasswordHash or
	// PasswordPepperVersion; existing credentials use PasswordHashUpdater so
	// every such write has the same CAS and monotonic-version guarantees.
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id string) error
	// List returns a page of users. It does NOT count the full result set —
	// paginated UIs fetch the total via Count on their own cadence so a
	// COUNT(*) isn't run on every page.
	List(ctx context.Context, filter UserFilter) ([]domain.User, error)
	// Count returns how many users match filter (Offset/Limit/OrderBy are
	// ignored).
	Count(ctx context.Context, filter UserFilter) (int, error)
	// CountByDay returns registrations per day matching filter (Offset/Limit
	// on filter are ignored — the result is naturally bounded by the date
	// range in filter.CreatedAfter/CreatedBefore).
	CountByDay(ctx context.Context, filter UserFilter) ([]api.DailyCount, error)
	// SetPasswordAndVerify atomically consumes a set-password code and sets the
	// password in one transaction. The token claim is conditional on the
	// token still being unused and is checked before the password write, so
	// two concurrent confirms cannot both consume the code. Returns false
	// when the code was already consumed or the user acquired a password
	// concurrently. A false result leaves the code and password untouched;
	// true means the password was set.
	SetPasswordAndVerify(ctx context.Context, userID string, passwordHash string, pepperVersion *uint32, tokenID string) (bool, error)
	SetBanStatus(ctx context.Context, userID string, isBanned bool, bannedAt *time.Time, updatedAt time.Time) error
	UpdateLastLoginAt(ctx context.Context, userID string, t time.Time) error
	SetTwoFactorEnabled(ctx context.Context, userID string, enabled bool, updatedAt time.Time) error
}
