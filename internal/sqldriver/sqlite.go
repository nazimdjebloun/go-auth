package sqldriver

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
)

// SQLiteForeignKeyDSN configures connection initialization, rather than running
// a PRAGMA once on a pool. Keep the filename verbatim: converting a plain path
// to a file: URI would reinterpret percent escapes and URI-only options.
func SQLiteForeignKeyDSN(driverName, dsn string) (string, error) {
	filename, query, _ := strings.Cut(dsn, "?")
	params, err := url.ParseQuery(query)
	if err != nil {
		return "", fmt.Errorf("goauth: parse sqlite DSN parameters: %w", err)
	}
	switch driverName {
	case "sqlite": // modernc.org/sqlite
		pragmas := params["_pragma"][:0]
		for _, pragma := range params["_pragma"] {
			name := strings.ToLower(strings.TrimSpace(pragma))
			if i := strings.IndexAny(name, "=( \t\r\n"); i >= 0 {
				name = name[:i]
			}
			if name != "foreign_keys" {
				pragmas = append(pragmas, pragma)
			}
		}
		params["_pragma"] = append(pragmas, "foreign_keys(1)")
	case "sqlite3": // github.com/mattn/go-sqlite3
		// mattn accepts both aliases; leaving _fk can override _foreign_keys.
		params.Del("_fk")
		params.Set("_foreign_keys", "1")
	default:
		return "", fmt.Errorf("goauth: unsupported sqlite driver %q", driverName)
	}
	return filename + "?" + params.Encode(), nil
}

// RequireSQLiteForeignKeys samples a connection without changing caller-owned
// state. With a borrowed pool this cannot certify other or future connections:
// the caller must configure their driver to enable enforcement on every one.
func RequireSQLiteForeignKeys(ctx context.Context, db *sql.DB) error {
	var enabled int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil {
		return fmt.Errorf("goauth: check sqlite foreign_keys: %w", err)
	}
	if enabled != 1 {
		return fmt.Errorf("goauth: sqlite foreign_keys must be enabled on every connection; configure the supplied *sql.DB with _pragma=foreign_keys(1) (modernc.org/sqlite) or _foreign_keys=1 (mattn/go-sqlite3); a single PRAGMA on a pool is insufficient")
	}
	return nil
}
