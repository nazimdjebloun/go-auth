package goauth

import (
	"database/sql"
	"errors"
	"fmt"
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
		errs = append(errs, errors.New("database: driver cannot be empty"))
	case DriverPostgres, DriverSQLite, DriverMySQL:
	default:
		errs = append(errs, fmt.Errorf(
			"database: unsupported driver %q; use DriverPostgres, DriverSQLite, or DriverMySQL",
			db.Driver,
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
		errs = append(errs, errors.New("database: one of URL, DB, or Pool is required"))
	case 1:
	default:
		errs = append(errs, errors.New("database: exactly one of URL, DB, or Pool must be set"))
	}
	if db.Pool != nil && db.Driver != DriverPostgres {
		errs = append(errs, errors.New("database: Pool requires DriverPostgres"))
	}
	return errs
}

// connectionLimits resolves defaults without mutating caller configuration.
func (c DatabaseConfig) connectionLimits() (int, int, error) {
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
		return 0, 0, fmt.Errorf("database: max_open_conns must not be negative")
	}
	if idle < 0 || idle > open {
		return 0, 0, fmt.Errorf("database: max_idle_conns must be between 0 and max_open_conns")
	}
	if c.ConnMaxLifetime < 0 || c.ConnMaxIdleTime < 0 {
		return 0, 0, fmt.Errorf("database: connection lifetimes must not be negative")
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
