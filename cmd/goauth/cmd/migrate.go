package cmd

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/internal/sqldriver"
	"github.com/spf13/cobra"

	_ "github.com/jackc/pgx/v5/stdlib" // Register the PostgreSQL database/sql driver.
	_ "modernc.org/sqlite"             // Register the SQLite database/sql driver.
)

func newMigrateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply the published standalone auth migration history",
		Long: `Installs auth objects in an unused namespace or applies pending published upgrades.
Auth history is separate from application migrations. Existing untracked auth
tables require explicit, validated baseline adoption. Stop auth traffic and
workers before running migrations. Incomplete history blocks further execution.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withMigrationDatabase(cmd, func(ctx context.Context, db *sql.DB, options goauth.MigrationOptions) error {
				status, err := goauth.Migrate(ctx, db, options)
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "goauth: auth schema revision %06d is complete (%s)\n", status.Revision, status.Dialect)
				return err
			})
		},
	}
	cmd.PersistentFlags().String("driver", "", "Database driver (postgres, sqlite, mysql)")
	cmd.PersistentFlags().String("dsn", "", "Database DSN")
	cmd.PersistentFlags().Duration("timeout", 30*time.Minute, "Overall operation timeout")
	cmd.PersistentFlags().Duration("lock-timeout", 30*time.Second, "Migration serialization and metadata-lock timeout")
	cmd.PersistentFlags().Duration("statement-timeout", 5*time.Minute, "Budget per migration statement, verification phase, or precondition phase")
	for _, name := range []string{"driver", "dsn"} {
		if err := cmd.MarkPersistentFlagRequired(name); err != nil {
			panic(err)
		}
	}
	cmd.AddCommand(newMigrationStatusCommand(), newMigrationVerifyCommand(), newMigrationAdoptCommand(), newMigrationRepairCommand(), newMigrationRetryCommand())
	return cmd
}

func newMigrationStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: "Report recorded auth history as JSON without executing DDL", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withMigrationDatabase(cmd, func(ctx context.Context, db *sql.DB, options goauth.MigrationOptions) error {
				status, err := goauth.GetMigrationStatus(ctx, db, options.Driver)
				if err != nil {
					return err
				}
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(status)
			})
		},
	}
}

func newMigrationVerifyCommand() *cobra.Command {
	return &cobra.Command{
		Use: "verify", Short: "Verify the tracked target schema and data postconditions", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withMigrationDatabase(cmd, func(ctx context.Context, db *sql.DB, options goauth.MigrationOptions) error {
				if err := goauth.VerifySchema(ctx, db, options); err != nil {
					return err
				}
				_, err := fmt.Fprintln(cmd.OutOrStdout(), "goauth: auth schema verification passed")
				return err
			})
		},
	}
}

func newMigrationAdoptCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "adopt", Short: "Validate an untracked baseline and record adoption without creation SQL", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			baseline, err := cmd.Flags().GetInt64("baseline")
			if err != nil {
				return err
			}
			if baseline <= 0 {
				return fmt.Errorf("goauth: --baseline must be positive")
			}
			return withMigrationDatabase(cmd, func(ctx context.Context, db *sql.DB, options goauth.MigrationOptions) error {
				status, err := goauth.AdoptSchema(ctx, db, goauth.BaselineAdoptionOptions{
					MigrationOptions: options, BaselineRevision: baseline,
				})
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "goauth: adopted verified auth baseline %06d\n", status.Revision)
				return err
			})
		},
	}
	cmd.Flags().Int64("baseline", 0, "Explicit supported baseline revision")
	mustMarkFlagRequired(cmd, "baseline")
	return cmd
}

func newMigrationRepairCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "repair", Short: "Verify and complete the specified incomplete migration without replaying SQL", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := cmd.Flags().GetInt64("id")
			if err != nil {
				return err
			}
			if id <= 0 {
				return fmt.Errorf("goauth: --id must be positive")
			}
			return withMigrationDatabase(cmd, func(ctx context.Context, db *sql.DB, options goauth.MigrationOptions) error {
				status, err := goauth.RepairMigration(ctx, db, goauth.MigrationRepairOptions{
					MigrationOptions: options, MigrationID: id,
				})
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "goauth: verified migration %06d and recorded completion\n", status.Revision)
				return err
			})
		},
	}
	cmd.Flags().Int64("id", 0, "Exact incomplete migration ID")
	mustMarkFlagRequired(cmd, "id")
	return cmd
}

func newMigrationRetryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "retry", Short: "Verify starting conditions and replay one incomplete upgrade with a published retry policy", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			id, err := cmd.Flags().GetInt64("id")
			if err != nil {
				return err
			}
			if id <= 0 {
				return fmt.Errorf("goauth: --id must be positive")
			}
			return withMigrationDatabase(cmd, func(ctx context.Context, db *sql.DB, options goauth.MigrationOptions) error {
				status, err := goauth.RetryMigration(ctx, db, goauth.MigrationRetryOptions{
					MigrationOptions: options, MigrationID: id,
				})
				if err != nil {
					return err
				}
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "goauth: retried and completed migration %06d; run migrate for remaining steps\n", status.Revision)
				return err
			})
		},
	}
	cmd.Flags().Int64("id", 0, "Exact incomplete migration ID with a published retry policy")
	mustMarkFlagRequired(cmd, "id")
	return cmd
}

func withMigrationDatabase(cmd *cobra.Command, run func(context.Context, *sql.DB, goauth.MigrationOptions) error) (err error) {
	driver, err := cmd.Flags().GetString("driver")
	if err != nil {
		return err
	}
	catalog, err := goauth.GetMigrationCatalog(driver)
	if err != nil {
		return err
	}
	dsn, err := cmd.Flags().GetString("dsn")
	if err != nil {
		return err
	}
	if dsn == "" {
		return fmt.Errorf("goauth: --dsn must not be empty")
	}
	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		return err
	}
	lockTimeout, err := cmd.Flags().GetDuration("lock-timeout")
	if err != nil {
		return err
	}
	statementTimeout, err := cmd.Flags().GetDuration("statement-timeout")
	if err != nil {
		return err
	}
	if timeout <= 0 || lockTimeout <= 0 || statementTimeout <= 0 {
		return fmt.Errorf("goauth: migration timeouts must be positive")
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	defer cancel()
	sqlDriver := sqldriver.SQLName(catalog.Dialect)
	if catalog.Dialect == "sqlite" {
		dsn, err = sqldriver.SQLiteForeignKeyDSN(sqlDriver, dsn)
		if err != nil {
			return &commandError{message: "goauth: invalid SQLite connection parameters", cause: err}
		}
	}
	db, err := sql.Open(sqlDriver, dsn)
	if err != nil {
		return &commandError{message: "goauth: could not open database; check connection settings", cause: err}
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			err = errors.Join(err, &commandError{message: "goauth: could not close database", cause: closeErr})
		}
	}()
	if err := db.PingContext(ctx); err != nil {
		return &commandError{message: "goauth: database connection failed; check connectivity and credentials", cause: err}
	}
	return migrationCommandError(run(ctx, db, goauth.MigrationOptions{
		Driver: catalog.Dialect, LockTimeout: lockTimeout, StatementTimeout: statementTimeout,
	}))
}

// CLI output omits raw driver messages, which may include credentials or data.
// Programmatic callers can still inspect the wrapped cause with errors.Is/As.
type commandError struct {
	message string
	cause   error
}

func (e *commandError) Error() string { return e.message }
func (e *commandError) Unwrap() error { return e.cause }

func migrationCommandError(err error) error {
	if err == nil {
		return nil
	}
	var failure *goauth.MigrationError
	prefix := "goauth: "
	if errors.As(err, &failure) {
		prefix = fmt.Sprintf("goauth: %s migration %06d, phase %s (dirty=%t, uncertain=%t): ",
			failure.Dialect, failure.MigrationID, failure.Phase, failure.Dirty, failure.Uncertain)
		// These configuration diagnostics are static and contain no driver data.
		if failure.Cause != nil {
			switch message := failure.Cause.Error(); message {
			case "goauth: MySQL migrations require session autocommit=1",
				"goauth: PostgreSQL migrations require session_replication_role=origin",
				"goauth: select a MySQL database before migrating":
				return &commandError{message: prefix + message, cause: err}
			}
		}
	}
	for _, known := range []error{
		context.Canceled, context.DeadlineExceeded,
		goauth.ErrUntrackedSchema, goauth.ErrDirtyMigration, goauth.ErrIncompatibleSchema,
		goauth.ErrSchemaDrift, goauth.ErrMigrationLockTimeout, goauth.ErrUnknownMigrationHistory,
		goauth.ErrMigrationChecksum, goauth.ErrMigrationPrecondition, goauth.ErrMigrationRetryUnsupported,
	} {
		if errors.Is(err, known) {
			message := known.Error()
			if known == goauth.ErrSchemaDrift && failure != nil {
				// Our drift diagnostics name published objects and differences.
				message = failure.Cause.Error()
			}
			return &commandError{message: prefix + message, cause: err}
		}
	}
	var mysqlError *mysql.MySQLError
	if errors.As(err, &mysqlError) {
		return &commandError{message: fmt.Sprintf("%sMySQL error %d", prefix, mysqlError.Number), cause: err}
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		return &commandError{message: prefix + "database SQLSTATE " + state.SQLState(), cause: err}
	}
	return &commandError{message: prefix + "operation failed; inspect database state before retrying", cause: err}
}

func init() { rootCmd.AddCommand(newMigrateCommand()) }
