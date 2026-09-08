package schema

import (
	_ "embed"
	"errors"
	"fmt"
)

// The DDL is compiled into the binary, so there is no .sql file to find on
// disk after `go get`. The paths below are relative to this package, which is
// where the .sql files live — the embed directives used to sit in the root
// package and reach down into this directory for files it already owned.

//go:embed postgres.sql
var postgresSchema string

//go:embed sqlite.sql
var sqliteSchema string

//go:embed mysql.sql
var mysqlSchema string

// byDriver keys on every spelling of a driver go-auth accepts, matching
// internal/sqldriver.SQLName — a name that resolves to a driver must also
// resolve to a schema.
var byDriver = map[string]string{
	"postgres": postgresSchema,
	"pg":       postgresSchema,
	"mysql":    mysqlSchema,
	"sqlite3":  sqliteSchema,
	"sqlite":   sqliteSchema,
}

// ErrUnsupportedDriver is returned (wrapped, with the offending name) by For
// when no embedded schema exists for the requested driver. Match it with
// errors.Is rather than comparing error strings.
var ErrUnsupportedDriver = errors.New("goauth: unsupported driver")

// For returns the embedded DDL for driver.
func For(driver string) (string, error) {
	s, ok := byDriver[driver]
	if !ok {
		return "", fmt.Errorf("%w %q — valid options: postgres, sqlite, mysql", ErrUnsupportedDriver, driver)
	}
	return s, nil
}
