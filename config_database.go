package goauth

import (
	"database/sql"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Driver identifies a supported database driver.
type Driver string

// DriverPostgres and the following values identify supported database drivers.
const (
	DriverPostgres Driver = "postgres"
	DriverSQLite   Driver = "sqlite3"
	DriverMySQL    Driver = "mysql"
)

// DatabaseConfig configures the database connection.
// Provide exactly one of URL, DB, or Pool. Pool requires DriverPostgres.
// NewConfig rejects unsupported drivers and conflicting connection sources.
// URL is the preferred option: the library opens, validates, and closes the
// connection automatically.
// New checks connectivity and recorded migration compatibility for every source
// before starting workers. Apply migrations separately before construction.
type DatabaseConfig struct {
	URL    string        // connection string (preferred)
	DB     *sql.DB       // pre-opened *sql.DB (library borrows, does not close)
	Pool   *pgxpool.Pool // pre-opened pgx pool (library borrows, does not close)
	Driver Driver        // DriverPostgres, DriverSQLite, DriverMySQL (required: NewConfig rejects an empty driver)

	// Limits apply only to URL-created databases, not borrowed DB or Pool.
	MaxOpenConns    int           // 0 defaults to 25 (PostgreSQL/MySQL), 1 (SQLite)
	MaxIdleConns    *int          // nil defaults to min(2, MaxOpenConns); explicit 0 disables idle retention
	ConnMaxLifetime time.Duration // 0 disables lifetime-based recycling
	ConnMaxIdleTime time.Duration // 0 disables idle-time recycling

	opened bool // internal — owns the SQL handle, including a borrowed-pool adapter
}

func (c *Config) validateDatabase() []error {
	db := c.app.Database
	var errs []error
	if _, _, err := db.connectionLimits(); err != nil {
		errs = append(errs, err)
	}
	switch db.Driver {
	case "":
		errs = append(errs, configIssue("App.Database.Driver", ConfigRequired, "database: driver cannot be empty"))
	case DriverPostgres, DriverSQLite, DriverMySQL:
	default:
		errs = append(errs, configIssue("App.Database.Driver", ConfigUnsupported,
			"database: unsupported driver; use DriverPostgres, DriverSQLite, or DriverMySQL",
		))
	}
	var sources int
	if db.URL != "" {
		sources++
	}
	if db.DB != nil {
		sources++
	}
	if db.Pool != nil {
		sources++
	}
	switch sources {
	case 0:
		errs = append(errs, configIssue("App.Database", ConfigRequired, "database: one of URL, DB, or Pool is required"))
	case 1:
	default:
		errs = append(errs, configIssue(
			"App.Database", ConfigConflict,
			"database: exactly one of URL, DB, or Pool must be set",
		))
	}
	if db.Pool != nil && db.Driver != DriverPostgres {
		errs = append(errs, configIssue("App.Database.Pool", ConfigConflict, "database: Pool requires DriverPostgres"))
	}
	return errs
}

// connectionLimits resolves defaults without mutating caller configuration.
func (c DatabaseConfig) connectionLimits() (int, int, error) {
	var errs []error
	open := c.MaxOpenConns
	if open == 0 {
		open = 25
		if c.Driver == DriverSQLite {
			open = 1
		}
	}
	idle := min(2, open)
	if c.MaxIdleConns != nil {
		idle = *c.MaxIdleConns
	}
	if open < 1 {
		errs = append(errs, configIssue("App.Database.MaxOpenConns", ConfigRange,
			"database: max_open_conns must not be negative"))
	}
	if c.MaxIdleConns != nil && (idle < 0 || (open > 0 && idle > open)) {
		errs = append(errs, configIssue("App.Database.MaxIdleConns", ConfigRange,
			"database: max_idle_conns must be between 0 and max_open_conns"))
	}
	if c.ConnMaxLifetime < 0 {
		errs = append(errs, configIssue("App.Database.ConnMaxLifetime", ConfigRange,
			"database: connection lifetimes must not be negative"))
	}
	if c.ConnMaxIdleTime < 0 {
		errs = append(errs, configIssue("App.Database.ConnMaxIdleTime", ConfigRange,
			"database: connection lifetimes must not be negative"))
	}
	if err := joinConfigIssues(errs...); err != nil {
		return 0, 0, err
	}
	return open, idle, nil
}
func (c DatabaseConfig) applyConnectionLimits(db *sql.DB) error {
	open, idle, err := c.connectionLimits()
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(open)
	db.SetMaxIdleConns(idle)
	db.SetConnMaxLifetime(c.ConnMaxLifetime)
	db.SetConnMaxIdleTime(c.ConnMaxIdleTime)
	return nil
}
