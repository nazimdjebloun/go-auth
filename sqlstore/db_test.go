package sqlstore

import "testing"

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
	// rebindQuery is a simple tokenizer and does not parse string literals.
	// $1 inside quotes is still replaced. This is a known limitation.
	got := rebindQuery("SELECT * FROM foo WHERE name = '$1'")
	want := "SELECT * FROM foo WHERE name = '?'"
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
