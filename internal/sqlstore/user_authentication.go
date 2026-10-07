package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/nazimdjebloun/go-auth/domain"
)

// GetByIDForUpdate holds the current user row through session/challenge issuance.
func (r *UserRepository) GetByIDForUpdate(ctx context.Context, id string) (*domain.User, error) {
	if _, ok := txFromContext(ctx); !ok {
		return nil, errors.New("authentication lock requires a transaction")
	}
	query := userByIDQuery + " FOR UPDATE"
	if r.db.Driver() == "sqlite" || r.db.Driver() == "sqlite3" {
		// Acquire the writer lock before reading; a stale SQLite snapshot must
		// fail its upgrade rather than authorize a write using old credentials.
		if _, err := r.db.ExecContext(ctx, "UPDATE users SET id = id WHERE id = $1", id); err != nil {
			return nil, fmt.Errorf("locking authentication state: %w", err)
		}
		query = userByIDQuery
	}
	user, err := r.scanRow(r.db.QueryRowContext(ctx, query, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return user, err
}
