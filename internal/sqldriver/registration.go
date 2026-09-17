package sqldriver

import (
	"database/sql"
	"fmt"
	"net/url"
	"strings"
)

// IsRegistered reports whether name is in database/sql's registered driver
// list. Library packages blank-import only the pgx stdlib driver, so SQLite
// and MySQL still need a blank import from the consumer (the goauth CLI's
// command package registers all three for its own use); this is what turns a
// missing import into a startup error naming the import instead of a
// query-time failure.
func IsRegistered(name string) bool {
	for _, d := range sql.Drivers() {
		if d == name {
			return true
		}
	}
	return false
}

// ResolveSQLiteName returns whichever of "sqlite" (modernc.org/sqlite,
// the documented driver) or "sqlite3" (mattn/go-sqlite3) is actually
// registered. IsRegistered accepts either name, so
// sql.Open must use the one that's really there instead of assuming
// "sqlite" — otherwise a consumer using mattn/go-sqlite3 passes validation
// and then fails with "unknown driver \"sqlite\"".
func ResolveSQLiteName() string {
	if IsRegistered("sqlite") {
		return "sqlite"
	}
	return "sqlite3"
}

// ValidateMySQLDSN rejects a MySQL DSN that's missing parseTime=true.
// go-sql-driver/mysql returns DATETIME/TIMESTAMP columns as []byte unless
// parseTime=true is set, and every sqlstore repository scans directly into
// time.Time fields — without it, the first query touching any date column
// fails with "unsupported Scan, storing driver.Value type []uint8 into type
// *time.Time". loc=UTC is recommended too: every timestamp in go-auth is
// computed via time.Now().UTC(), and without loc=UTC the driver parses
// returned times in the local server timezone, skewing expiry/TTL checks.
func ValidateMySQLDSN(dsn string) error {
	_, params, _ := strings.Cut(dsn, "?")
	values, err := url.ParseQuery(params)
	if err != nil || !mysqlBoolParam(values.Get("parseTime")) {
		return fmt.Errorf(
			"goauth: mysql DSN is missing \"parseTime=true\" — go-sql-driver/mysql " +
				"returns DATETIME/TIMESTAMP columns as []byte without it, which breaks " +
				"every query that scans a time.Time field. Add \"?parseTime=true&loc=UTC\" " +
				"to your DSN (loc=UTC is strongly recommended since go-auth computes all " +
				"timestamps in UTC).",
		)
	}
	return nil
}

// mysqlBoolParam mirrors go-sql-driver/mysql's own DSN boolean parsing
// (readBool): "1"/"true" (case-insensitive) are true, everything else false.
func mysqlBoolParam(v string) bool {
	switch strings.ToLower(v) {
	case "1", "true":
		return true
	default:
		return false
	}
}
