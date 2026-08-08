package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

func TestRebindQuery_PostgresPassthrough(t *testing.T) {
	// Rebind is called via DB — we test rebindQuery directly for MySQL/SQLite
	// behavior, and verify DB.Rebind passes through for postgres.
	db := NewDB(nil, "postgres")
	q := "SELECT * FROM users WHERE id = $1"
	if got := db.Rebind(q); got != q {
		t.Errorf("expected passthrough %q, got %q", q, got)
	}
}

func TestRebindQuery_SingleParam(t *testing.T) {
	got := rebindQuery("SELECT * FROM users WHERE id = $1")
	want := "SELECT * FROM users WHERE id = ?"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindQuery_MultipleParams(t *testing.T) {
	got := rebindQuery("INSERT INTO users (name, email) VALUES ($1, $2)")
	want := "INSERT INTO users (name, email) VALUES (?, ?)"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindQuery_DoubleDigitParams(t *testing.T) {
	got := rebindQuery("SELECT * FROM users WHERE id IN ($1, $2, $10, $11)")
	want := "SELECT * FROM users WHERE id IN (?, ?, ?, ?)"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindQuery_NoParams(t *testing.T) {
	got := rebindQuery("SELECT 1")
	want := "SELECT 1"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindQuery_DollarInString(t *testing.T) {
	got := rebindQuery("SELECT * FROM foo WHERE name = '$1'")
	want := "SELECT * FROM foo WHERE name = '$1'"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindQuery_Mixed(t *testing.T) {
	got := rebindQuery("UPDATE users SET name = $1, cost = $10 WHERE id = $2")
	want := "UPDATE users SET name = ?, cost = ? WHERE id = ?"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindQuery_Empty(t *testing.T) {
	got := rebindQuery("")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestRebindQuery_MySQLDriver(t *testing.T) {
	db := NewDB(nil, "mysql")
	q := "SELECT * FROM users WHERE id = $1"
	got := db.Rebind(q)
	want := "SELECT * FROM users WHERE id = ?"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestRebindQuery_SQLiteDriver(t *testing.T) {
	db := NewDB(nil, "sqlite3")
	q := "SELECT * FROM users WHERE id = $1"
	got := db.Rebind(q)
	want := "SELECT * FROM users WHERE id = ?"
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestDriver_MysqlDriversMap(t *testing.T) {
	if !mysqlDrivers["mysql"] {
		t.Error("expected mysql in mysqlDrivers")
	}
	if !mysqlDrivers["sqlite3"] {
		t.Error("expected sqlite3 in mysqlDrivers")
	}
	if !mysqlDrivers["sqlite"] {
		t.Error("expected sqlite in mysqlDrivers")
	}
	if mysqlDrivers["postgres"] {
		t.Error("expected postgres NOT in mysqlDrivers")
	}
}

// ---------------------------------------------------------------------------
// WithTx: regression tests for actual transactional atomicity.
//
// A prior version of WithTx stored its *sql.Tx in context but ExecContext/
// QueryContext/QueryRowContext never looked for it, so every "transactional"
// statement silently autocommitted against the pool instead of running
// inside the transaction. These tests exercise that behavior directly
// against a real SQLite file (a shared in-memory DB isn't used because each
// pooled connection to ":memory:" is its own separate database, which would
// make the isolation check meaningless — see newSQLiteTestDB).
// ---------------------------------------------------------------------------

func newSQLiteTestDB(t *testing.T) *DB {
	t.Helper()
	f, err := os.CreateTemp("", "goauth-db-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	rawDB, err := sql.Open("sqlite", f.Name()+"?_pragma=busy_timeout(10000)")
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}
	t.Cleanup(func() {
		rawDB.Close()
		os.Remove(f.Name())
	})
	if _, err := rawDB.Exec("CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatal(err)
	}
	return NewDB(rawDB, "sqlite")
}

func countKV(t *testing.T, db *DB) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM kv").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWithTx_CommitsOnSuccess(t *testing.T) {
	db := newSQLiteTestDB(t)

	err := db.WithTx(context.Background(), func(ctx context.Context) error {
		if _, err := db.ExecContext(ctx, "INSERT INTO kv (k, v) VALUES ($1, $2)", "a", "1"); err != nil {
			return err
		}
		_, err := db.ExecContext(ctx, "INSERT INTO kv (k, v) VALUES ($1, $2)", "b", "2")
		return err
	})
	if err != nil {
		t.Fatalf("WithTx returned error: %v", err)
	}
	if n := countKV(t, db); n != 2 {
		t.Errorf("expected 2 rows after commit, got %d", n)
	}
}

func TestWithTx_RollsBackOnError(t *testing.T) {
	db := newSQLiteTestDB(t)
	sentinel := errors.New("boom")

	err := db.WithTx(context.Background(), func(ctx context.Context) error {
		if _, err := db.ExecContext(ctx, "INSERT INTO kv (k, v) VALUES ($1, $2)", "a", "1"); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel error, got %v", err)
	}
	if n := countKV(t, db); n != 0 {
		t.Errorf("expected rollback to leave 0 rows, got %d — WithTx is not providing real atomicity", n)
	}
}

func TestWithTx_StatementsScopedToTransaction(t *testing.T) {
	db := newSQLiteTestDB(t)

	var countDuringTx int
	err := db.WithTx(context.Background(), func(ctx context.Context) error {
		if _, err := db.ExecContext(ctx, "INSERT INTO kv (k, v) VALUES ($1, $2)", "a", "1"); err != nil {
			return err
		}
		// Read through the raw pool (a context with no tx), bypassing the
		// active transaction — this proves the insert is actually scoped to
		// the transaction rather than having already autocommitted.
		return db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM kv").Scan(&countDuringTx)
	})
	if err != nil {
		t.Fatalf("WithTx returned error: %v", err)
	}
	if countDuringTx != 0 {
		t.Errorf("expected the insert to be invisible outside the transaction before commit, saw %d rows", countDuringTx)
	}
	if n := countKV(t, db); n != 1 {
		t.Errorf("expected 1 row after commit, got %d", n)
	}
}

func TestWithTx_NestedJoinsOuterTransaction(t *testing.T) {
	db := newSQLiteTestDB(t)

	err := db.WithTx(context.Background(), func(ctx context.Context) error {
		return db.WithTx(ctx, func(ctx context.Context) error {
			_, err := db.ExecContext(ctx, "INSERT INTO kv (k, v) VALUES ($1, $2)", "a", "1")
			return err
		})
	})
	if err != nil {
		t.Fatalf("WithTx returned error: %v", err)
	}
	if n := countKV(t, db); n != 1 {
		t.Errorf("expected 1 row after nested WithTx commits, got %d", n)
	}
}
