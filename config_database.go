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
// Provide one of URL, DB, or Pool. URL is the preferred option —
// the library will open, validate, and close the connection automatically.
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
	var errs []error
	if _, _, err := c.app.Database.connectionLimits(); err != nil {
		errs = append(errs, err)
	}
	if c.app.Database.Driver == "" {
		errs = append(errs, errors.New("database: driver cannot be empty"))
	}
	if c.app.Database.URL == "" && c.app.Database.DB == nil && c.app.Database.Pool == nil {
		errs = append(errs, errors.New("database: one of URL, DB, or Pool is required"))
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
