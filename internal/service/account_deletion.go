package service

import (
	"context"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// Narrow capability interfaces for account deletion. Each is satisfied by
// the corresponding sqlstore repository; declaring them here keeps the
// coordinator testable with small doubles and keeps dependencies minimal.

type deletionOrgs interface {
	ListUserMemberships(ctx context.Context, userID string) ([]port.AccountOrgMembership, error)
	GetMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error)
	RemoveMember(ctx context.Context, orgID, userID string, expectRole domain.OrgRole) (bool, error)
	TryDecrementOrgOwnerCount(ctx context.Context, orgID string) error
	DecrementUserOrgOwnerCount(ctx context.Context, userID string) error
	DecrementOrgMemberCount(ctx context.Context, orgID string) error
}

type deletionSessions interface {
	DeleteAllForUser(ctx context.Context, userID string) error
}

type deletionUsers interface {
	port.AdminGuardStore
	GetByID(ctx context.Context, userID string) (*domain.User, error)
}

// AccountDeletion is the one owner of the account-deletion invariants:
// every surviving organization's member/owner counters stay correct, and
// the deletion can never remove the last usable (non-banned) admin. The
// whole operation runs in one transaction, so a failure anywhere rolls back
// the session revocation and counter upkeep instead of leaving them
// committed behind a partially applied deletion.
//
// Services receive this coordinator through AttachAccountDeletion. Missing
// wiring fails closed; there is no non-transactional deletion fallback.
type AccountDeletion struct {
	tx       port.TxManager
	orgs     deletionOrgs // nil when organizations are disabled
	sessions deletionSessions
	users    deletionUsers
}

func NewAccountDeletion(tx port.TxManager, orgs deletionOrgs, sessions deletionSessions, users deletionUsers) *AccountDeletion {
	return &AccountDeletion{tx: tx, orgs: orgs, sessions: sessions, users: users}
}

// DeleteUser performs the invariant-safe account deletion: unwind every
// organization membership with its counter upkeep (blocking a sole org
// owner), revoke all sessions, and delete the user under the last-usable-
// admin guard — all in one transaction.
func (d *AccountDeletion) DeleteUser(ctx context.Context, userID string) error {
	return d.DeleteUserAndRecord(ctx, userID, nil)
}

// DeleteUserAndRecord performs the deletion and invokes record inside the
// same transaction after every state mutation succeeds. A record failure
// therefore rolls the deletion back when the audit policy is fail-closed.
func (d *AccountDeletion) DeleteUserAndRecord(ctx context.Context, userID string, record func(context.Context) error) error {
	return d.users.WithAdminGuard(ctx, func(txCtx context.Context) error {
		if d.orgs != nil {
			memberships, err := d.orgs.ListUserMemberships(txCtx, userID)
			if err != nil {
				return err
			}
			for _, m := range memberships {
				// Re-read inside the transaction: the authoritative row and
				// role the guarded writes below assert against.
				member, err := d.orgs.GetMembership(txCtx, m.OrgID, userID)
				if err != nil {
					return err
				}
				if member == nil {
					continue
				}
				removed, err := d.orgs.RemoveMember(txCtx, m.OrgID, userID, member.Role)
				if err != nil {
					return err
				}
				if !removed {
					// The membership's role changed under us; the transaction
					// aborts before any counter moved, so failing here is
					// safe (same contract as OrgService.RemoveMember).
					return domain.ErrOrgMemberConflict
				}
				if member.Role == domain.OrgRoleOwner {
					// TryDecrementOrgOwnerCount is guarded: it matches zero
					// rows — and fails — when the org would lose its last
					// owner. Rolling back unwinds this org's counters and
					// any earlier memberships in the loop.
					if err := d.orgs.TryDecrementOrgOwnerCount(txCtx, m.OrgID); err != nil {
						return err
					}
					if err := d.orgs.DecrementUserOrgOwnerCount(txCtx, userID); err != nil {
						return err
					}
				}
				if err := d.orgs.DecrementOrgMemberCount(txCtx, m.OrgID); err != nil {
					return err
				}
			}
		}

		if err := d.sessions.DeleteAllForUser(txCtx, userID); err != nil {
			return err
		}

		deleted, err := d.users.DeleteWithAdminGuard(txCtx, userID)
		if err != nil {
			return err
		}
		if !deleted {
			// The guard matched nothing: either the row vanished mid-flight
			// or this was the last usable admin. Distinguish by re-reading.
			user, err := d.users.GetByID(txCtx, userID)
			if err != nil {
				return err
			}
			if user == nil {
				return domain.ErrUserNotFound
			}
			return domain.ErrCannotDeleteLastAdmin
		}
		if record != nil {
			return record(txCtx)
		}
		return nil
	})
}
