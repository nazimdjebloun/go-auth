package goauth

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"
)

func TestDatabaseBudget_LimitsAndCancellation(t *testing.T) {
	cfg := &Config{app: AppConfig{Database: DatabaseConfig{Driver: DriverSQLite, URL: ":memory:", MaxOpenConns: 2}}}
	_, db, err := openDatabase(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	first, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = first.Close() }()
	second, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if conn, err := db.Conn(ctx); !errors.Is(err, context.DeadlineExceeded) {
		if conn != nil {
			if closeErr := conn.Close(); closeErr != nil {
				t.Error(closeErr)
			}
		}
		t.Fatalf("exhausted pool: %v", err)
	}
	if stats := db.Stats(); stats.OpenConnections != 2 || stats.WaitCount == 0 {
		t.Fatalf("unexpected pool stats: %+v", stats)
	}
}

func TestDatabaseBudget_DefaultMemoryPersists(t *testing.T) {
	cfg := &Config{app: AppConfig{Database: DatabaseConfig{Driver: DriverSQLite, URL: ":memory:"}}}
	_, db, err := openDatabase(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec("CREATE TABLE budget_test (id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO budget_test VALUES (1)"); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM budget_test").Scan(&count); err != nil || count != 1 {
		t.Fatalf("memory database lost: count=%d err=%v", count, err)
	}
}

func TestDatabaseBudget_BorrowedSQLUnchanged(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(7)
	cfg, err := NewConfig(minimalOpts(WithApp(AppConfig{
		Name: "app", BaseURL: "https://example.com",
		Database: DatabaseConfig{Driver: DriverSQLite, DB: db, MaxOpenConns: 1},
	}))...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if db.Stats().MaxOpenConnections != 7 {
		t.Fatal("borrowed limit changed")
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("borrowed DB closed: %v", err)
	}
}

func TestDatabaseBudget_ValidationAndDefaults(t *testing.T) {
	for _, driver := range []Driver{DriverPostgres, DriverMySQL, DriverSQLite} {
		c := DatabaseConfig{Driver: driver}
		open, idle, err := c.connectionLimits()
		want := 25
		if driver == DriverSQLite {
			want = 1
		}
		if err != nil || open != want || idle != min(2, want) {
			t.Fatalf("%s: %d %d %v", driver, open, idle, err)
		}
	}
	negative, excessive, zero := -1, 4, 0
	for _, c := range []DatabaseConfig{
		{MaxOpenConns: -1}, {MaxIdleConns: &negative},
		{MaxOpenConns: 2, MaxIdleConns: &excessive},
		{ConnMaxLifetime: -time.Second}, {ConnMaxIdleTime: -time.Second},
	} {
		cfg := validTestConfig()
		c.Driver, c.URL = DriverSQLite, ":memory:"
		cfg.app.Database = c
		if len(cfg.validateDatabase()) == 0 {
			t.Fatalf("accepted invalid budget: %+v", c)
		}
	}
	c := DatabaseConfig{MaxIdleConns: &zero}
	if _, idle, err := c.connectionLimits(); err != nil || idle != 0 {
		t.Fatalf("explicit zero: %d %v", idle, err)
	}
	cfg := &Config{app: AppConfig{Database: c}}
	clone := cfg.clone()
	*clone.app.Database.MaxIdleConns = 1
	if zero != 0 {
		t.Fatal("clone shares idle configuration pointer")
	}
}
