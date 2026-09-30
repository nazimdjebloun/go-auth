package port

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// InviteFilter narrows and orders platform invite queries.
type InviteFilter struct {
	Search         *string
	Status         *string
	OrderBy        api.InviteSortField
	OrderDirection api.SortDirection
	Offset         int
	Limit          int
}

// InviteRepository stores platform invitations.
type InviteRepository interface {
	Create(ctx context.Context, invite *domain.Invite) error
	GetByID(ctx context.Context, id string) (*domain.Invite, error)
	GetByCode(ctx context.Context, code string) (*domain.Invite, error)
	GetByEmail(ctx context.Context, email string) (*domain.Invite, error)
	// List returns a page of invites; use Count for the total.
	List(ctx context.Context, filter InviteFilter) ([]domain.Invite, error)
	// Count returns how many invites match filter (Offset/Limit ignored).
	Count(ctx context.Context, filter InviteFilter) (int, error)
	Update(ctx context.Context, invite *domain.Invite) error
	// Revoke changes only a pending/expired invite to revoked. It never
	// replaces a code or overwrites an accepted invite.
	Revoke(ctx context.Context, id string) (bool, error)
	// RotateCode refreshes a pending/expired invite only while its code still
	// matches expectedCode. Accepted/revoked invites cannot become pending.
	RotateCode(ctx context.Context, id, expectedCode, newCode string, expiresAt time.Time) (bool, error)
	Delete(ctx context.Context, id string) error
	// ClaimInvite atomically sets status to 'accepted' only if currently 'pending'.
	// Returns true if the invite was claimed, false if already accepted/revoked/expired.
	ClaimInvite(ctx context.Context, code string, acceptedAt time.Time) (bool, error)
}
