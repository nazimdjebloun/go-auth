package goauth

import (
	"database/sql"
	"fmt"
)

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
