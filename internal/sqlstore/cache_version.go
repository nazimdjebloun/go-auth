package sqlstore

import (
	"context"
	"database/sql"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// versionedUpdate adds a fresh cache identity to a static UPDATE. Assigning it
// in the guarded statement preserves affected-row and transaction semantics.
// Callers supply repository-owned SQL, never a request-controlled statement.
var versionParameter = regexp.MustCompile(`\$([0-9]+)`)

func versionedUpdate(query string, args []any) (string, []any) {
	// Keep argument order textual as well as numbered: MySQL and SQLite's
	// positional rebinding must see the new SET parameter before all others.
	query = versionParameter.ReplaceAllStringFunc(query, func(p string) string {
		n, _ := strconv.Atoi(p[1:])
		return "$" + strconv.Itoa(n+1)
	})
	query = strings.Replace(query, "SET ", "SET cache_version = $1, ", 1)
	return query, append([]any{uuid.NewString()}, args...)
}

func (d *DB) execVersioned(ctx context.Context, query string, args ...any) (sql.Result, error) {
	query, args = versionedUpdate(query, args)
	return d.ExecContext(ctx, query, args...)
}

func (d *DB) queryVersioned(ctx context.Context, query string, args ...any) *sql.Row {
	query, args = versionedUpdate(query, args)
	return d.QueryRowContext(ctx, query, args...)
}
