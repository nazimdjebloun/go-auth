package sqlstore

import (
	"context"
	"database/sql"
	"strings"

	"github.com/nazimdjebloun/go-auth/port"
)

var _ port.TxManager = (*DB)(nil)

type DB struct {
	*sql.DB
	driver string
}

func NewDB(db *sql.DB, driver string) *DB {
	return &DB{DB: db, driver: driver}
}

var mysqlDrivers = map[string]bool{
	"mysql":   true,
	"sqlite3": true,
	"sqlite":  true,
}

func (d *DB) Driver() string {
	return d.driver
}

func (d *DB) Rebind(query string) string {
	if mysqlDrivers[d.driver] {
		return rebindQuery(query)
	}
	return query
}

func rebindQuery(query string) string {
	var b strings.Builder
	b.Grow(len(query))
	i := 0
	for i < len(query) {
		if query[i] == '$' && i+1 < len(query) && query[i+1] >= '1' && query[i+1] <= '9' {
			b.WriteByte('?')
			i++
			for i < len(query) && query[i] >= '0' && query[i] <= '9' {
				i++
			}
		} else {
			b.WriteByte(query[i])
			i++
		}
	}
	return b.String()
}

func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return d.DB.ExecContext(ctx, d.Rebind(query), args...)
}

func (d *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return d.DB.QueryContext(ctx, d.Rebind(query), args...)
}

func (d *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return d.DB.QueryRowContext(ctx, d.Rebind(query), args...)
}

type txKey struct{}

type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (d *DB) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	tx, err := d.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	ctx = context.WithValue(ctx, txKey{}, tx)
	if err := fn(ctx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (d *DB) getExecutor(ctx context.Context) executor {
	if tx, ok := ctx.Value(txKey{}).(executor); ok {
		return tx
	}
	return d
}
