package goauth

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSQLiteForeignKeyDSN(t *testing.T) {
	for _, tt := range []struct {
		name, driver, dsn, param, want string
	}{
		{"modernc memory", "sqlite", ":memory:", "_pragma", "foreign_keys(1)"},
		{"modernc override", "sqlite", "plain%23.db?_pragma=foreign_keys(0)&_pragma=busy_timeout(1000)", "_pragma", "foreign_keys(1)"},
		{"mattn alias", "sqlite3", "file:test.db?_fk=off&_foreign_keys=0", "_foreign_keys", "1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sqliteForeignKeyDSN(tt.driver, tt.dsn)
			if err != nil {
				t.Fatal(err)
			}
			filename, query, _ := strings.Cut(got, "?")
			original, _, _ := strings.Cut(tt.dsn, "?")
			if filename != original {
				t.Fatalf("filename changed: %q != %q", filename, original)
			}
			params, err := url.ParseQuery(query)
			if err != nil {
				t.Fatal(err)
			}
			values := params[tt.param]
			if len(values) == 0 || values[len(values)-1] != tt.want {
				t.Fatalf("params: %v", params)
			}
			if params.Has("_fk") {
				t.Fatal("mattn alias retained")
			}
			if tt.name == "modernc override" && (len(values) != 2 || values[0] != "busy_timeout(1000)") {
				t.Fatalf("unrelated pragma lost: %v", values)
			}
		})
	}
	if _, err := sqliteForeignKeyDSN("sqlite", "file:test.db?bad=%zz"); err == nil {
		t.Fatal("accepted malformed parameters")
	}
	if _, err := sqliteForeignKeyDSN("unknown", "test.db"); err == nil {
		t.Fatal("accepted unknown driver")
	}
}

func TestOpenDatabase_SQLiteEveryConnection(t *testing.T) {
	// Hold both connections at once: two sequential pool queries may exercise
	// only one physical connection and miss the original per-connection defect.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	filename := filepath.Join(t.TempDir(), "literal%23 name.db")
	cfg := &Config{app: AppConfig{Database: DatabaseConfig{Driver: DriverSQLite, URL: filename}}}
	_, db, err := openDatabase(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	if !cfg.app.Database.opened {
		t.Fatal("owned database not recorded")
	}
	if _, err := os.Stat(filename); err != nil {
		t.Fatalf("plain filename semantics changed: %v", err)
	}
	db.SetMaxOpenConns(2)
	first, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	for i, conn := range []*sql.Conn{first, second} {
		var enabled int
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&enabled); err != nil || enabled != 1 {
			t.Fatalf("connection %d enforcement = %d, err %v", i, enabled, err)
		}
	}
	for _, stmt := range []string{
		"CREATE TABLE parent (id INTEGER PRIMARY KEY)",
		"CREATE TABLE child (parent_id INTEGER REFERENCES parent(id) ON DELETE CASCADE)",
		"INSERT INTO parent VALUES (1)",
		"INSERT INTO child VALUES (1)",
	} {
		if _, err := first.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := second.ExecContext(ctx, "DELETE FROM parent WHERE id = 1"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := first.QueryRowContext(ctx, "SELECT COUNT(*) FROM child").Scan(&count); err != nil || count != 0 {
		t.Fatalf("cascade left %d children, err %v", count, err)
	}
	for i, conn := range []*sql.Conn{first, second} {
		if _, err := conn.ExecContext(ctx, "INSERT INTO child VALUES (999)"); err == nil {
			t.Fatalf("connection %d accepted orphan", i)
		}
	}
	// Closing idle connections forces the next acquisition to initialize anew.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	db.SetMaxIdleConns(0)
	if err := requireSQLiteForeignKeys(ctx, db.DB); err != nil {
		t.Fatalf("replacement connection: %v", err)
	}
}
