package cmd

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/nazimdjebloun/go-auth"
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

		schema, err := goauth.GetSchema(driver)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
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

		for _, stmt := range goauth.SplitSQL(schema) {
			if _, err := db.Exec(stmt); err != nil {
				log.Fatalf("goauth: migration failed: %v\nStatement: %s", err, stmt)
			}
			fmt.Println("OK:", stmt)
		}
		fmt.Println("goauth: migration complete!")
	},
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
