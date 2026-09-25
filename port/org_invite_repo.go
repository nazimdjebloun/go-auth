package port

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// OrgInviteFilter narrows and orders OrgInviteRepository.ListByOrgID for one
// org. Status is derived from ExpiresAt vs the query time, not a stored
// column — there is no persisted invite status.
type OrgInviteFilter struct {
	Role           *domain.OrgRole
	Status         *string // "pending" or "expired"; nil means both
	Search         *string // matches invite email
	OrderBy        api.OrgInviteSortField
	OrderDirection api.SortDirection
	Offset         int
	Limit          int // 0 means unlimited
}

// OrgInviteRepository stores invitations to join organizations.
type OrgInviteRepository interface {
	Create(ctx context.Context, invite *domain.OrgInvite) error
	GetByID(ctx context.Context, id string) (*domain.OrgInvite, error)
	GetByCodeHash(ctx context.Context, codeHash string) (*domain.OrgInvite, error)
	// ListByOrgID returns a page of one org's invites; use CountByOrgID for the total.
	ListByOrgID(ctx context.Context, orgID string, filter OrgInviteFilter) ([]domain.OrgInvite, error)
	// CountByOrgID returns how many of orgID's invites match filter (Offset/Limit ignored).
	CountByOrgID(ctx context.Context, orgID string, filter OrgInviteFilter) (int, error)
	Update(ctx context.Context, invite *domain.OrgInvite) error
	Delete(ctx context.Context, id string) error
	// ClaimInvite atomically consumes the invite row, but only while it
	// still carries codeHash and has not expired. The hash binds the claim
	// to the code the caller validated: an admin resend/rotation replaces
	// the stored hash, so a redemption that looked the invite up under the
	// old code loses the claim and must use the fresh code. Returns false
	// when the invite was already claimed, rotated, deleted, or expired.
	ClaimInvite(ctx context.Context, id, codeHash string) (bool, error)
}
