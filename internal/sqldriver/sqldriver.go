// Package sqldriver maps the driver names go-auth accepts onto the
// database/sql driver names the supported backends actually register.
//
// It exists so the library and the goauth CLI cannot disagree. They are
// separate modules and each previously carried its own copy of this switch,
// with different alias coverage — a driver added to one would silently not
// work in the other.
package sqldriver

// SQLName returns the database/sql driver name to open for one of the driver
// names go-auth accepts.
//
// The accepted aliases mirror the keys of the embedded schema map in the root
// package (postgres/pg, sqlite/sqlite3, mysql), so any name that resolves to a
// schema also resolves to a driver. An unrecognized name is returned unchanged
// and left for sql.Open to reject.
//
// SQLite is the one case a caller may need to override: this returns "sqlite"
// (modernc.org/sqlite, the documented driver), but mattn/go-sqlite3 registers
// itself as "sqlite3". Callers that accept either must check which is actually
// registered rather than trusting this name.
func SQLName(name string) string {
	switch name {
	case "postgres", "pg":
		return "pgx"
	case "sqlite", "sqlite3":
		return "sqlite"
	default:
		return name
	}
}
