package cmd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/internal/schema"
	"github.com/nazimdjebloun/go-auth/internal/sqldriver"
	"github.com/spf13/cobra"

	"github.com/go-sql-driver/mysql"
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

		sqlDriver := sqldriver.SQLName(driver)
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

// applySchema replays the canonical bootstrap DDL, not versioned upgrades.
// Tables and non-MySQL indexes use IF NOT EXISTS; MySQL duplicate-index
// errors are ignored only for CREATE INDEX statements. Existing definitions
// are not checked or altered. A failure may leave earlier DDL applied.
func applySchema(ctx context.Context, db *sql.DB, driver string) error {
	schemaSQL, err := goauth.GetSchema(driver)
	if err != nil {
		return err
	}
	for _, stmt := range schema.SplitSQL(schemaSQL) {
		_, err := db.ExecContext(ctx, stmt)
		if err != nil && driver == "mysql" && isCreateIndex(stmt) && isMySQLDuplicateIndexErr(err) {
			// MySQL has no CREATE INDEX IF NOT EXISTS. A rerun of the
			// canonical schema over an already-migrated database must stay
			// a no-op rather than aborting on the first existing index, so
			// error 1061 (duplicate key name) on a CREATE INDEX is treated
			// as already-applied. Any other error still fails the run.
			fmt.Println("SKIP (already exists):", stmt)
			continue
		}
		if err != nil {
			return fmt.Errorf("goauth: migration failed: %w\nStatement: %s", err, stmt)
		}
		fmt.Println("OK:", stmt)
	}
	return nil
}

// Only the canonical CREATE INDEX forms may treat error 1061 as a rerun.
func isCreateIndex(stmt string) bool {
	fields := strings.Fields(stmt)
	if len(fields) < 4 || !strings.EqualFold(fields[0], "CREATE") {
		return false
	}
	if strings.EqualFold(fields[1], "UNIQUE") {
		fields = fields[1:]
	}
	return strings.EqualFold(fields[1], "INDEX")
}

func isMySQLDuplicateIndexErr(err error) bool {
	var mysqlErr *mysql.MySQLError
	return errors.As(err, &mysqlErr) && mysqlErr.Number == 1061
}

func init() {
	migrateCmd.Flags().String("driver", "", "Database driver (postgres, sqlite, mysql)")
	migrateCmd.Flags().String("dsn", "", "Database DSN")
	migrateCmd.MarkFlagRequired("driver")
	migrateCmd.MarkFlagRequired("dsn")
	rootCmd.AddCommand(migrateCmd)
}
