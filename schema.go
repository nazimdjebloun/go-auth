package goauth

import (
	"os"

	"github.com/nazimdjebloun/go-auth/internal/schema"
)

// The schema itself — the embedded .sql files and the statement splitter —
// lives in internal/schema, alongside the .sql files it embeds. What follows is
// only the public surface over it.

// ErrUnsupportedDriver is returned (wrapped, with the offending name) by
// GetSchema when no embedded schema exists for the requested driver. Match it
// with errors.Is rather than comparing error strings.
var ErrUnsupportedDriver = schema.ErrUnsupportedDriver

// GetSchema returns the embedded DDL for driver. The error wraps
// ErrUnsupportedDriver for any driver the library has no schema for.
func GetSchema(driver string) (string, error) {
	return schema.For(driver)
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
	return os.WriteFile(outPath, []byte(sql), 0600)
}
