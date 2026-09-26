package port

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// OrgMemberFilter narrows and orders OrgCRUD.ListMembers within one org.
// orgID stays a separate positional argument on ListMembers rather than a
// field here — it's a hard scoping boundary, not an optional filter.
type OrgMemberFilter struct {
	Role           *domain.OrgRole
	Search         *string // matches member's name or email
	OrderBy        api.OrgMemberSortField
	OrderDirection api.SortDirection
	Offset         int
	Limit          int // 0 means unlimited
}

// UserOrgFilter narrows and orders OrgCRUD.ListUserOrgs for one user.
type UserOrgFilter struct {
	Search         *string         // matches org name or slug
	Role           *domain.OrgRole // nil = all roles, else owner/admin/member
	OrderBy        api.UserOrgSortField
	OrderDirection api.SortDirection
	Offset         int
	Limit          int // 0 means unlimited
}

// OrgFilter narrows and orders OrgCRUD.List — the platform-admin, cross-org
// listing (as opposed to UserOrgFilter, which is scoped to one user's
// memberships).
type OrgFilter struct {
	Search         *string // matches org name or slug
	CreatedAfter   *time.Time
	CreatedBefore  *time.Time
	OrderBy        api.OrgSortField
	OrderDirection api.SortDirection
	Offset         int
	Limit          int // 0 means unlimited
}

// OrgCRUD covers organization and membership records themselves — creating,
// reading, updating, and deleting orgs and their members.
type OrgCRUD interface {
	Create(ctx context.Context, org *domain.Organization) error
	GetByID(ctx context.Context, id string) (*domain.Organization, error)
	GetBySlug(ctx context.Context, slug string) (*domain.Organization, error)
	Update(ctx context.Context, org *domain.Organization) error
	// Delete removes the organization row. It returns false when no row
	// matched — a concurrent delete already removed it — so the caller
	// must roll back any invariant upkeep instead of applying it twice.
	Delete(ctx context.Context, id string) (bool, error)
	// List returns a page of organizations (platform admin); use Count for
	// the total.
	List(ctx context.Context, filter OrgFilter) ([]domain.Organization, error)
	// Count returns how many organizations match filter (Offset/Limit ignored).
	Count(ctx context.Context, filter OrgFilter) (int, error)

	AddMember(ctx context.Context, member *domain.OrgMember) error
	// RemoveMember deletes the (orgID, userID) membership, but only while it
	// still holds expectRole — a compare-and-swap guarding the denormalized
	// owner/member counts against a concurrent removal or role change. It
	// returns false when no row matched, in which case the caller must roll
	// back any counter upkeep instead of applying it to a row that is gone
	// or no longer has that role.
	RemoveMember(ctx context.Context, orgID, userID string, expectRole domain.OrgRole) (bool, error)
	// UpdateMemberRole sets the role from expectRole to newRole, but only
	// while the row still holds expectRole — the same compare-and-swap
	// guard as RemoveMember. It returns false when no row matched.
	// Callers must resolve the no-change case themselves and never call
	// with expectRole == newRole (MySQL's changed-rows accounting reports 0
	// for value-identical writes, so it cannot distinguish them).
	UpdateMemberRole(ctx context.Context, orgID, userID string, expectRole, newRole domain.OrgRole) (bool, error)
	GetMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error)
	// LockMembership reads the current role while preventing a concurrent
	// removal or role change until the caller's transaction commits. It must
	// be called inside TxManager.WithTx.
	LockMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error)
	// ListMembers returns a page of an org's members; use CountMembers for the total.
	ListMembers(ctx context.Context, orgID string, filter OrgMemberFilter) ([]domain.OrgMemberDetail, error)
	CountMembers(ctx context.Context, orgID string, filter OrgMemberFilter) (int, error)
	// ListUserOrgs returns a page of a user's orgs; use CountUserOrgs for the total.
	ListUserOrgs(ctx context.Context, userID string, filter UserOrgFilter) ([]domain.Organization, error)
	CountUserOrgs(ctx context.Context, userID string, filter UserOrgFilter) (int, error)
}

// OrgLimitCounters maintains the denormalized owner/member counts that back
// SecurityConfig's org limits (max orgs owned per user, max members per
// org) — invariant-maintenance for that feature, not core org CRUD. Each
// Increment enforces its cap atomically in SQL (guarded update, not
// read-then-write) and returns an error if the cap is already reached.
type OrgLimitCounters interface {
	IncrementUserOrgOwnerCount(ctx context.Context, userID string, maxOrgs int) error
	DecrementUserOrgOwnerCount(ctx context.Context, userID string) error
	IncrementOrgMemberCount(ctx context.Context, orgID string, maxMembers int) error
	DecrementOrgMemberCount(ctx context.Context, orgID string) error
	TryDecrementOrgOwnerCount(ctx context.Context, orgID string) error
	IncrementOrgOwnerCount(ctx context.Context, orgID string) error
	DecrementOwnerCountForOrgOwners(ctx context.Context, orgID string) error
}

// OrgRepository composes the two facets above for sqlstore and any consumer
// that wants the full org contract in one implementation.
type OrgRepository interface {
	OrgCRUD
	OrgLimitCounters
}
