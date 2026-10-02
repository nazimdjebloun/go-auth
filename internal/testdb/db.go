// Package testdb provisions isolated databases for cross-dialect tests.
package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nazimdjebloun/go-auth/internal/schema"
	_ "modernc.org/sqlite" // Register the driver used by isolated SQLite fixtures.
)

type connection struct{ driver, dsn string }

var connections sync.Map

// Selected returns the requested backend, defaulting to SQLite for local runs.
func Selected() string {
	if driver := os.Getenv("GOAUTH_TEST_DRIVER"); driver != "" {
		return driver
	}
	return "sqlite"
}

// DSN returns the existing integration-test DSN for a backend.
func DSN(driver string) string {
	switch driver {
	case "postgres":
		return os.Getenv("GOAUTH_POSTGRES_DSN")
	case "mysql":
		return os.Getenv("GOAUTH_MYSQL_TEST_DSN")
	default:
		return ""
	}
}

// Driver returns the dialect recorded when a test database was opened.
func Driver(db *sql.DB) string {
	if info, ok := connections.Load(db); ok {
		return info.(connection).driver
	}
	panic("testdb: unregistered database")
}

// Open creates a fresh database and registers cleanup. It never uses the DSN's
// database for test writes. Explicitly selected external backends cannot skip.
func Open(t *testing.T, driver, dsn string) *sql.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	name := "goauth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	var db *sql.DB
	var err error
	var destroy func()
	switch driver {
	case "sqlite":
		dsn = filepath.Join(t.TempDir(), "auth.db") + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)"
		db, err = sql.Open("sqlite", dsn)
	case "postgres":
		if dsn == "" {
			t.Fatal("GOAUTH_POSTGRES_DSN is required for PostgreSQL tests")
		}
		cfg, parseErr := pgx.ParseConfig(dsn)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		// Match the UTC MySQL fixture and CI service regardless of the
		// developer's PostgreSQL server timezone.
		cfg.RuntimeParams["timezone"] = "UTC"
		admin := stdlib.OpenDB(*cfg)
		if _, err = admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
			_ = admin.Close()
			t.Fatal(err)
		}
		destroy = func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			_, dropErr := admin.ExecContext(cleanupCtx, "DROP DATABASE "+name+" WITH (FORCE)")
			if dropErr != nil {
				t.Error(dropErr)
			}
			_ = admin.Close()
		}
		cfg.Database = name
		dsn = stdlib.RegisterConnConfig(cfg)
		t.Cleanup(func() { stdlib.UnregisterConnConfig(dsn) })
		db, err = sql.Open("pgx", dsn)
	case "mysql":
		if dsn == "" {
			t.Fatal("GOAUTH_MYSQL_TEST_DSN is required for MySQL tests")
		}
		cfg, parseErr := mysql.ParseDSN(dsn)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		cfg.DBName = ""
		cfg.ParseTime = true
		cfg.Loc = time.UTC
		admin, openErr := sql.Open("mysql", cfg.FormatDSN())
		if openErr != nil {
			t.Fatal(openErr)
		}
		if _, err = admin.ExecContext(ctx, "CREATE DATABASE "+name+" CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"); err != nil {
			_ = admin.Close()
			t.Fatal(err)
		}
		destroy = func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanupCancel()
			_, dropErr := admin.ExecContext(cleanupCtx, "DROP DATABASE "+name)
			if dropErr != nil {
				t.Error(dropErr)
			}
			_ = admin.Close()
		}
		cfg.DBName = name
		dsn = cfg.FormatDSN()
		db, err = sql.Open("mysql", dsn)
	default:
		t.Fatalf("unsupported GOAUTH_TEST_DRIVER %q", driver)
	}
	if destroy != nil {
		t.Cleanup(destroy)
	}
	if err != nil {
		t.Fatal(err)
	}
	connections.Store(db, connection{driver, dsn})
	db.SetMaxOpenConns(12)
	db.SetMaxIdleConns(4)
	t.Cleanup(func() {
		connections.Delete(db)
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("%s unavailable: %v", driver, err)
	}
	t.Logf("database backend: %s", driver)
	return db
}

// OpenSelected opens the backend selected by GOAUTH_TEST_DRIVER.
func OpenSelected(t *testing.T) *sql.DB {
	t.Helper()
	driver := Selected()
	return Open(t, driver, DSN(driver))
}

// SecondPool opens an independent pool against the same isolated database.
func SecondPool(t *testing.T, db *sql.DB) *sql.DB {
	t.Helper()
	info, ok := connections.Load(db)
	if !ok {
		t.Fatal("unregistered test database")
	}
	c := info.(connection)
	driver := c.driver
	if driver == "postgres" {
		driver = "pgx"
	}
	other, err := sql.Open(driver, c.dsn)
	if err != nil {
		t.Fatal(err)
	}
	connections.Store(other, c)
	other.SetMaxOpenConns(12)
	t.Cleanup(func() {
		connections.Delete(other)
		if err := other.Close(); err != nil {
			t.Error(err)
		}
	})
	return other
}

// SQL translates fixture question-mark placeholders for PostgreSQL. Quoted SQL
// content is preserved. Production queries use their own repository rebinding.
func SQL(db *sql.DB, query string) string {
	if Driver(db) != "postgres" {
		return query
	}
	var out strings.Builder
	quoted := false
	n := 0
	for i := 0; i < len(query); i++ {
		ch := query[i]
		if ch == '\'' {
			out.WriteByte(ch)
			if quoted && i+1 < len(query) && query[i+1] == '\'' {
				i++
				out.WriteByte(ch)
				continue
			}
			quoted = !quoted
		} else if ch == '?' && !quoted {
			n++
			fmt.Fprintf(&out, "$%d", n)
		} else {
			out.WriteByte(ch)
		}
	}
	return out.String()
}

// Apply loads the complete canonical schema, including all indexes.
func Apply(t *testing.T, db *sql.DB) {
	t.Helper()
	script, err := schema.For(Driver(db))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schema.SplitSQL(script) {
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("%s schema: %v\n%s", Driver(db), err, stmt)
		}
	}
}

// FailWrites installs a real database failure at a credential transaction's
// intermediate statement. The returned function removes it so retry is tested.
func FailWrites(t *testing.T, db *sql.DB, name, table, operation, condition string) func() {
	t.Helper()
	identifier := regexp.MustCompile(`^[a-z_]+$`)
	if !identifier.MatchString(name) || !identifier.MatchString(table) {
		t.Fatal("invalid fixture trigger identifier")
	}
	if operation != "UPDATE" && operation != "INSERT" && operation != "DELETE" {
		t.Fatal("invalid fixture trigger operation")
	}
	if condition != "" && condition != "NEW.event_type = 'session.refreshed'" {
		t.Fatal("unsupported fixture trigger condition")
	}
	var create, drop string
	if condition == "" {
		condition = "TRUE"
	}
	switch Driver(db) {
	case "sqlite":
		create = "CREATE TRIGGER " + name + " BEFORE " + operation + " ON " + table + " WHEN " + condition + " BEGIN SELECT RAISE(FAIL, 'injected failure'); END"
		drop = "DROP TRIGGER " + name
	case "mysql":
		create = "CREATE TRIGGER " + name + " BEFORE " + operation + " ON " + table + " FOR EACH ROW BEGIN IF " + condition + " THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected failure'; END IF; END"
		drop = "DROP TRIGGER " + name
	case "postgres":
		//nolint:gosec // Test-only DDL; identifiers, operation, and condition are allowlisted above.
		fn := "CREATE FUNCTION " + name + "_fn() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF " + condition + " THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$"
		if _, err := db.Exec(fn); err != nil {
			t.Fatal(err)
		}
		create = "CREATE TRIGGER " + name + " BEFORE " + operation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION " + name + "_fn()"
		drop = "DROP TRIGGER " + name + " ON " + table
	}
	if _, err := db.Exec(create); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	remove := func() {
		once.Do(func() {
			if _, err := db.Exec(drop); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(remove)
	return remove
}
