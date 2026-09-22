package sqlstore

import (
	"context"
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

var _ port.AdminGuardStore = (*UserRepository)(nil)

type adminGuardKey struct{}
type adminGuardState struct{ db *DB }

// WithAdminGuard locks existing users in primary-key order. Every reduction
// in the usable-admin set takes these same locks before reading the set. In
// particular, these are locking/current reads on MySQL, not a repeatable-read
// snapshot established by an earlier query. New users can only increase the
// set; they cannot invalidate a permitted reduction. No singleton schema row
// or process-local mutex is required. The cost is serializing admin mutations
// with other user writes; keep callbacks short and free of external I/O.
//
// SQLite has no row locks: a no-op write obtains its database writer lock
// before any read. If an outer transaction already has a stale snapshot,
// SQLite refuses the upgrade and the error rolls back instead of proceeding.
// Deadlock/serialization errors likewise propagate: callers may retry the
// whole operation, never just a write made from an old decision.
func (r *UserRepository) WithAdminGuard(ctx context.Context, fn func(context.Context) error) error {
	if state, ok := ctx.Value(adminGuardKey{}).(adminGuardState); ok && state.db == r.db {
		return fn(ctx)
	}
	return r.db.WithTx(ctx, func(ctx context.Context) error {
		query := "SELECT id FROM users ORDER BY id FOR UPDATE"
		if r.db.Driver() == "sqlite" || r.db.Driver() == "sqlite3" {
			if _, err := r.db.ExecContext(ctx, "UPDATE users SET id = id WHERE 1 = 0"); err != nil {
				return fmt.Errorf("locking account mutations: %w", err)
			}
			query = "SELECT id FROM users ORDER BY id"
		}
		rows, err := r.db.QueryContext(ctx, query)
		if err != nil {
			return fmt.Errorf("locking account mutations: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				return err
			}
		}
		err = rows.Err()
		closeErr := rows.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		return fn(context.WithValue(ctx, adminGuardKey{}, adminGuardState{db: r.db}))
	})
}

// adminReductionAllowed runs only under WithAdminGuard. Locking reads are
// necessary even after locking: MySQL's ordinary SELECT may see an older
// snapshot if a caller already queried before joining the guard.
func (r *UserRepository) adminReductionAllowed(ctx context.Context, userID string) (bool, error) {
	query := "SELECT id, role, is_banned FROM users ORDER BY id"
	if r.db.Driver() != "sqlite" && r.db.Driver() != "sqlite3" {
		query += " FOR UPDATE"
	}
	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return false, err
	}
	found, targetUsable, otherUsable := false, false, false
	for rows.Next() {
		var id string
		var role domain.Role
		var banned bool
		if err := rows.Scan(&id, &role, &banned); err != nil {
			_ = rows.Close()
			return false, err
		}
		usable := role == domain.RoleAdmin && !banned
		if id == userID {
			found, targetUsable = true, usable
		} else if usable {
			otherUsable = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return false, err
	}
	if err := rows.Close(); err != nil {
		return false, fmt.Errorf("admin guard rows close: %w", err)
	}
	if !found {
		return false, domain.ErrUserNotFound
	}
	return !targetUsable || otherUsable, nil
}

func (r *UserRepository) DeleteWithAdminGuard(ctx context.Context, userID string) (bool, error) {
	var changed bool
	err := r.WithAdminGuard(ctx, func(ctx context.Context) error {
		allowed, err := r.adminReductionAllowed(ctx, userID)
		if err != nil || !allowed {
			return err
		}
		changed, err = affected(r.db.ExecContext(ctx, userDeleteQuery, userID))
		return err
	})
	return changed && err == nil, err
}

func (r *UserRepository) BanWithAdminGuard(ctx context.Context, userID string, banned bool, bannedAt *time.Time, updatedAt time.Time) (bool, error) {
	var changed bool
	err := r.WithAdminGuard(ctx, func(ctx context.Context) error {
		allowed, err := r.adminReductionAllowed(ctx, userID)
		if err != nil {
			return err
		}
		if banned && !allowed {
			return nil
		}
		_, err = r.db.ExecContext(ctx, userBanQuery, banned, bannedAt, updatedAt, userID)
		changed = err == nil // matched target is locked; MySQL no-op writes report zero
		return err
	})
	return changed && err == nil, err
}

func (r *UserRepository) DemoteWithAdminGuard(ctx context.Context, userID string, role domain.Role, updatedAt time.Time) (bool, error) {
	var changed bool
	err := r.WithAdminGuard(ctx, func(ctx context.Context) error {
		allowed, err := r.adminReductionAllowed(ctx, userID)
		if err != nil {
			return err
		}
		if role != domain.RoleAdmin && !allowed {
			return nil
		}
		_, err = r.db.ExecContext(ctx, userSetRoleQuery, role, updatedAt, userID)
		changed = err == nil
		return err
	})
	return changed && err == nil, err
}
