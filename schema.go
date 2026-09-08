package goauth

import (
	"errors"
	"fmt"

	"github.com/nazimdjebloun/go-auth/internal/schema"
)

// ErrUnsupportedDriver is returned (wrapped, with the offending name) by
// GetSchema when no embedded schema exists for the requested driver. Match it
// with errors.Is rather than comparing error strings.
var ErrUnsupportedDriver = errors.New("goauth: unsupported driver")

// newUnsupportedDriverError wraps ErrUnsupportedDriver with the driver name the
// caller asked for and the set of names that would have worked.
func newUnsupportedDriverError(driver string) error {
	return fmt.Errorf("%w %q — valid options: postgres, sqlite, mysql", ErrUnsupportedDriver, driver)
}

// GetSchema returns the embedded DDL for driver. The error wraps
// ErrUnsupportedDriver for any driver the library has no schema for.
func GetSchema(driver string) (string, error) {
	s, ok := driverSchemas[driver]
	if !ok {
		return "", newUnsupportedDriverError(driver)
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
