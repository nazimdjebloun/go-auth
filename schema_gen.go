package goauth

import (
	_ "embed"
	"os"
)

//go:embed internal/schema/postgres.sql
var embeddedPostgresSchema string

//go:embed internal/schema/sqlite.sql
var embeddedSQLiteSchema string

//go:embed internal/schema/mysql.sql
var embeddedMySQLSchema string

var driverSchemas = map[string]string{
	"postgres": embeddedPostgresSchema,
	"pg":       embeddedPostgresSchema,
	"mysql":    embeddedMySQLSchema,
	"sqlite3":  embeddedSQLiteSchema,
	"sqlite":   embeddedSQLiteSchema,
}

func GenerateSchema(driver, outPath string) error {
	schema, err := GetSchema(driver)
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, []byte(schema), 0644)
}
