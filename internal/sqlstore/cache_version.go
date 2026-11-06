package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var versionParameter = regexp.MustCompile(`\$([0-9]+)`)

var errVersionedUpdate = errors.New("sqlstore: versioned update requires a literal uppercase SET clause followed by a space")

// versionedUpdate adds a fresh cache identity to a static UPDATE. Callers supply
// repository-owned SQL with a literal "SET " assignment clause, never request
// text. Reject unsupported formatting before changing placeholders or arguments.
func versionedUpdate(query string, args []any) (string, []any, error) {
	if !strings.Contains(query, "SET ") {
		return "", nil, errVersionedUpdate
	}
	// Keep argument order textual as well as numbered: MySQL and SQLite's
	// positional rebinding must see the new SET parameter before all others.
	query = versionParameter.ReplaceAllStringFunc(query, func(p string) string {
		n, _ := strconv.Atoi(p[1:])
		return "$" + strconv.Itoa(n+1)
	})
	query = strings.Replace(query, "SET ", "SET cache_version = $1, ", 1)
	return query, append([]any{uuid.NewString()}, args...), nil
}

func (d *DB) execVersioned(ctx context.Context, query string, args ...any) (sql.Result, error) {
	query, args, err := versionedUpdate(query, args)
	if err != nil {
		return nil, err
	}
	return d.ExecContext(ctx, query, args...)
}

type scanError struct{ err error }

func (s scanError) Scan(...any) error { return s.err }

func (d *DB) queryVersioned(ctx context.Context, query string, args ...any) scanner {
	query, args, err := versionedUpdate(query, args)
	if err != nil {
		return scanError{err: err}
	}
	return d.QueryRowContext(ctx, query, args...)
}
