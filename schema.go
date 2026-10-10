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
// statements on semicolons, respecting single-quoted strings and dropping
// line comments. It is a bootstrap utility, not the versioned migration parser.
func SplitSQL(sql string) []string {
	return schema.SplitSQL(sql)
}

// GenerateSchema writes the desired DDL for driver to outPath for review. Use
// ExportSchema to include reference/catalog artifacts and Migrate to apply
// tracked auth upgrades separately from application migrations.
func GenerateSchema(driver, outPath string) error {
	sql, err := GetSchema(driver)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(sql), 0600)
}
