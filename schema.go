package goauth

import (
	"fmt"

	"github.com/nazimdjebloun/go-auth/internal/schema"
)

func ErrNoSchema(driver string) error {
	return fmt.Errorf("goauth: unsupported driver %q — valid options: postgres, sqlite, mysql", driver)
}

func GetSchema(driver string) (string, error) {
	s, ok := driverSchemas[driver]
	if !ok {
		return "", ErrNoSchema(driver)
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
