package goauth

import (
	_ "embed"
	"errors"
	"fmt"
	"os"

	"github.com/nazimdjebloun/go-auth/internal/schema"
)

// The DDL ships inside the binary, so there is no .sql file to find on disk
// after `go get`. Apply it with the goauth CLI's migrate command, or read it
// out with GetSchema and run it yourself.

//go:embed internal/schema/postgres.sql
var embeddedPostgresSchema string

//go:embed internal/schema/sqlite.sql
var embeddedSQLiteSchema string

//go:embed internal/schema/mysql.sql
var embeddedMySQLSchema string

// driverSchemas keys on every spelling of a driver go-auth accepts, matching
// internal/sqldriver.SQLName — a name that resolves to a driver must also
// resolve to a schema.
var driverSchemas = map[string]string{
	"postgres": embeddedPostgresSchema,
	"pg":       embeddedPostgresSchema,
	"mysql":    embeddedMySQLSchema,
	"sqlite3":  embeddedSQLiteSchema,
	"sqlite":   embeddedSQLiteSchema,
}

// ErrUnsupportedDriver is returned (wrapped, with the offending name) by
// GetSchema when no embedded schema exists for the requested driver. Match it
// with errors.Is rather than comparing error strings.
var ErrUnsupportedDriver = errors.New("goauth: unsupported driver")

// GetSchema returns the embedded DDL for driver. The error wraps
// ErrUnsupportedDriver for any driver the library has no schema for.
func GetSchema(driver string) (string, error) {
	s, ok := driverSchemas[driver]
	if !ok {
		return "", fmt.Errorf("%w %q — valid options: postgres, sqlite, mysql", ErrUnsupportedDriver, driver)
	}
	return s, nil
}

// SplitSQL splits a schema string (as returned by GetSchema) into individual
// statements on semicolons, respecting quoted strings and dropping
// comment-only fragments — the same splitter the goauth CLI's migrate
// command uses to run the embedded schema one statement at a time.
func SplitSQL(sql string) []string {
	return schema.SplitSQL(sql)
}

// GenerateSchema writes the embedded DDL for driver to outPath, for a project
// that manages migrations with its own tooling and wants the statements as a
// file it can check in.
func GenerateSchema(driver, outPath string) error {
	sql, err := GetSchema(driver)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(sql), 0644)
}
