// Package sqlstore implements go-auth repositories with database/sql.
package sqlstore

import (
	"context"
	"database/sql"
	"strings"

	"github.com/nazimdjebloun/go-auth/port"
)

var _ port.TxManager = (*DB)(nil)

// DB wraps sql.DB with driver-aware queries and transactions.
type DB struct {
	*sql.DB
	driver string
}

// NewDB returns a DB for the given driver.
func NewDB(db *sql.DB, driver string) *DB {
	return &DB{DB: db, driver: driver}
}

var positionalParamDrivers = map[string]bool{
	"mysql":   true,
	"sqlite3": true,
	"sqlite":  true,
}

// Driver returns the configured driver name.
func (d *DB) Driver() string {
	return d.driver
}

// Rebind converts numbered placeholders for the configured driver.
func (d *DB) Rebind(query string) string {
	if positionalParamDrivers[d.driver] {
		return rebindQuery(query)
	}
	return query
}

// UsesPositionalParams reports whether this database takes positional "?"
// placeholders (MySQL and the SQLite drivers) rather than PostgreSQL's
// numbered "$N". The same driver classification drives DB.Rebind above; the
// repositories additionally consult it for the dialect-specific LIKE operator
// (PostgreSQL's ILIKE vs MySQL/SQLite's LIKE with an adjusted search term).
func (d *DB) UsesPositionalParams() bool {
	return positionalParamDrivers[d.driver]
}

func rebindQuery(query string) string {
	var b strings.Builder
	b.Grow(len(query))
	inQuote := false
	i := 0
	for i < len(query) {
		if inQuote {
			b.WriteByte(query[i])
			if query[i] == '\'' && i+1 < len(query) && query[i+1] == '\'' {
				b.WriteByte('\'')
				i += 2
				continue
			}
			if query[i] == '\'' {
				inQuote = false
			}
			i++
			continue
		}
		if query[i] == '\'' {
			inQuote = true
			b.WriteByte('\'')
			i++
			continue
		}
		if query[i] == '$' && i+1 < len(query) && query[i+1] >= '1' && query[i+1] <= '9' {
			b.WriteByte('?')
			i++
			for i < len(query) && query[i] >= '0' && query[i] <= '9' {
				i++
			}
			continue
		}
		b.WriteByte(query[i])
		i++
	}
	return b.String()
}

type txKey struct{}

// txFromContext returns the *sql.Tx started by WithTx, if ctx was derived
// from its callback. Every repository call goes through ExecContext /
// QueryContext / QueryRowContext below, so this is the single place that
// decides whether a statement runs inside the active transaction or
// autocommits directly against the pool.
func txFromContext(ctx context.Context) (*sql.Tx, bool) {
	tx, ok := ctx.Value(txKey{}).(*sql.Tx)
	return tx, ok
}

// ExecContext executes on the active transaction or connection pool.
func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	query = d.Rebind(query)
	if tx, ok := txFromContext(ctx); ok {
		return tx.ExecContext(ctx, query, args...)
	}
	return d.DB.ExecContext(ctx, query, args...)
}

// QueryContext queries the active transaction or connection pool.
func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	query = d.Rebind(query)
	if tx, ok := txFromContext(ctx); ok {
		return tx.QueryContext(ctx, query, args...)
	}
	return d.DB.QueryContext(ctx, query, args...)
}

// QueryRowContext queries one row from the active transaction or connection pool.
func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	query = d.Rebind(query)
	if tx, ok := txFromContext(ctx); ok {
		return tx.QueryRowContext(ctx, query, args...)
	}
	return d.DB.QueryRowContext(ctx, query, args...)
}

// WithTx runs fn inside a single database transaction. Every repository
// call made with the ctx passed to fn — via ExecContext/QueryContext/
// QueryRowContext above — runs on that transaction, not the pool, so a
// failure partway through fn rolls back everything fn already did.
func (d *DB) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := txFromContext(ctx); ok {
		// Already inside a transaction — join it instead of starting a
		// nested one, which would open a second connection and could
		// deadlock against the still-open outer transaction on
		// single-writer databases like SQLite.
		return fn(ctx)
	}

	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	// A panic in fn must not pin the transaction (and its pooled
	// connection): the deferred Rollback releases it during unwinding, then
	// the panic keeps propagating. After a successful Commit this is a
	// harmless no-op returning ErrTxDone.
	defer func() { _ = tx.Rollback() }()

	ctx = context.WithValue(ctx, txKey{}, tx)
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit()
}
