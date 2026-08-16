package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/internal/schema"
	"github.com/spf13/cobra"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run auth schema migrations against a database",
	Long: `Connects to the database using the provided DSN and driver,
then applies the canonical auth schema to it.

Supported drivers: postgres, sqlite, mysql`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		driver, _ := cmd.Flags().GetString("driver")
		dsn, _ := cmd.Flags().GetString("dsn")

		if driver == "" {
			fmt.Fprintln(os.Stderr, "goauth: --driver is required")
			os.Exit(1)
		}
		if dsn == "" {
			fmt.Fprintln(os.Stderr, "goauth: --dsn is required")
			os.Exit(1)
		}

		sqlDriver := sqlDriverName(driver)
		db, err := sql.Open(sqlDriver, dsn)
		if err != nil {
			log.Fatalf("goauth: failed to connect: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			log.Fatalf("goauth: ping failed: %v", err)
		}

		if err := applySchema(context.Background(), db, driver); err != nil {
			log.Fatal(err)
		}
		fmt.Println("goauth: migration complete!")
	},
}

// applySchema fetches the embedded schema for driver and applies it to db
// one statement at a time. Every statement in the embedded schemas is
// written as CREATE ... IF NOT EXISTS, so a second call against an
// already-migrated database is expected to succeed as a no-op rather than
// error.
func applySchema(ctx context.Context, db *sql.DB, driver string) error {
	schemaSQL, err := goauth.GetSchema(driver)
	if err != nil {
		return err
	}
	for _, stmt := range schema.SplitSQL(schemaSQL) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("goauth: migration failed: %w\nStatement: %s", err, stmt)
		}
		fmt.Println("OK:", stmt)
	}
	return nil
}

func sqlDriverName(driver string) string {
	switch driver {
	case "postgres", "pg":
		return "pgx"
	case "sqlite", "sqlite3":
		return "sqlite"
	default:
		return driver
	}
}

func init() {
	migrateCmd.Flags().String("driver", "", "Database driver (postgres, sqlite, mysql)")
	migrateCmd.Flags().String("dsn", "", "Database DSN")
	migrateCmd.MarkFlagRequired("driver")
	migrateCmd.MarkFlagRequired("dsn")
	rootCmd.AddCommand(migrateCmd)
}
