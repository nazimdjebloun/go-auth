package port

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// AccountOrgMembership is one organization membership a deleted user holds.
type AccountOrgMembership struct {
	OrgID string
	Role  domain.OrgRole
}

// AdminGuardStore serializes changes that can remove a usable (non-banned)
// administrator across connections and processes. Services fail closed when
// this capability is unavailable. A count subquery alone is not sufficient.
type AdminGuardStore interface {
	// WithAdminGuard opens/joins a transaction and holds shared database locks
	// until the outermost commit/rollback. All callback operations use its context.
	WithAdminGuard(ctx context.Context, fn func(context.Context) error) error
	// DeleteWithAdminGuard deletes the user, but only while the deletion
	// leaves at least one usable (non-banned) admin.
	DeleteWithAdminGuard(ctx context.Context, userID string) (bool, error)
	// BanWithAdminGuard sets ban status, but only while banning the target
	// leaves at least one usable admin.
	BanWithAdminGuard(ctx context.Context, userID string, isBanned bool, bannedAt *time.Time, updatedAt time.Time) (bool, error)
	// DemoteWithAdminGuard sets the user's role, but only while a demotion
	// from admin leaves at least one usable admin. Promotion and no-op
	// writes are unaffected by the guard.
	DemoteWithAdminGuard(ctx context.Context, userID string, role domain.Role, updatedAt time.Time) (bool, error)
}
