package sqlstore

import (
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/nazimdjebloun/go-auth/port"
)

// isDuplicateKeyErr reports whether err is a unique-constraint violation
// from the given driver (r.db.Driver(): "postgres", "mysql", "sqlite3", or
// "sqlite"). Postgres, via the already-required pgx/v5 dependency, has a
// typed error to check. MySQL's driver (github.com/go-sql-driver/mysql) and
// SQLite's (modernc.org/sqlite) are both optional dependencies this module
// doesn't import — see auth.go's driver-registration check — so both are
// detected by matching the driver's error message instead.
func isDuplicateKeyErr(driver string, err error) bool {
	if err == nil {
		return false
	}
	switch driver {
	case "postgres":
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "23505"
	case "mysql":
		msg := err.Error()
		return strings.Contains(msg, "Error 1062") || strings.Contains(msg, "Duplicate entry")
	case "sqlite", "sqlite3":
		return strings.Contains(err.Error(), "UNIQUE constraint failed")
	}
	return false
}

// wrapCreateErr translates err into port.ErrDuplicateKey when it's a
// unique-constraint violation, so callers can react to the race with
// errors.Is(err, port.ErrDuplicateKey) without depending on any driver's
// error type. Any other error passes through unchanged.
func wrapCreateErr(driver string, err error) error {
	if isDuplicateKeyErr(driver, err) {
		return port.ErrDuplicateKey
	}
	return err
}
