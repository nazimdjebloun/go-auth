package cmd

import (
	"context"
	"database/sql"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/internal/schema"
)

// Requires a dedicated test server and CREATE/DROP DATABASE privileges. Only
// the unique database created here is changed; the DSN database is not used.
func TestApplySchema_MySQL(t *testing.T) {
	dsn := os.Getenv("GOAUTH_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_MYSQL_TEST_DSN not set (dedicated MySQL 8.4 test server required)")
	}
	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.DBName = ""
	admin, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()
	name := "goauth_schema_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	// Deliberately conflict with the schema's utf8mb4 table defaults.
	if _, err := admin.Exec("CREATE DATABASE " + name + " CHARACTER SET latin1 COLLATE latin1_swedish_ci"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec("DROP DATABASE " + name); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}()
	cfg.DBName = name
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	script, err := goauth.GetSchema("mysql")
	if err != nil {
		t.Fatal(err)
	}
	// Simulate interruption after the first table and index, then retry.
	for _, stmt := range schema.SplitSQL(script)[:2] {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := applySchema(ctx, db, "mysql"); err != nil {
			t.Fatalf("bootstrap %d: %v", i, err)
		}
		assertSchemaInventory(t, db, "mysql", script)
	}
	longText := strings.Repeat("a", 2048)
	if _, err := db.Exec("INSERT INTO users (id, email, name) VALUES ('test-user', 'test@example.com', ?)", longText); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO sessions (id, user_id, token_hash, user_agent, expires_at) VALUES ('test-session', 'test-user', 'AbC', ?, CURRENT_TIMESTAMP)", longText); err != nil {
		t.Fatal(err)
	}
	var ua, ip, refresh string
	if err := db.QueryRow("SELECT user_agent, ip_address, refresh_token_hash FROM sessions WHERE id = 'test-session'").Scan(&ua, &ip, &refresh); err != nil {
		t.Fatal(err)
	}
	if ua != longText || ip != "" || refresh != "" {
		t.Fatal("TEXT capacity/defaults were not preserved")
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions WHERE token_hash = 'abc'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("token hashes must be case sensitive")
	}
	if _, err := db.Exec("INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES ('bad-fk', 'missing', 'different', CURRENT_TIMESTAMP)"); err == nil {
		t.Fatal("foreign key did not reject missing user")
	}
}

func TestApplySchema_SQLite_Inventory(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	script, err := goauth.GetSchema("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := applySchema(context.Background(), db, "sqlite"); err != nil {
			t.Fatal(err)
		}
		assertSchemaInventory(t, db, "sqlite", script)
	}
}

// Raw canonical DDL is deliberately parsed independently of SplitSQL.
func assertSchemaInventory(t *testing.T, db *sql.DB, dialect, script string) {
	t.Helper()
	definition := regexp.MustCompile(`(?m)^CREATE (TABLE|INDEX)(?: IF NOT EXISTS)? ([a-z_]+)`)
	for _, match := range definition.FindAllStringSubmatch(script, -1) {
		kind, name := strings.ToLower(match[1]), match[2]
		var count int
		var err error
		if dialect == "sqlite" {
			err = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?", kind, name).Scan(&count)
		} else if kind == "table" {
			err = db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?", name).Scan(&count)
		} else {
			err = db.QueryRow("SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND index_name = ?", name).Scan(&count)
		}
		if err != nil || count == 0 {
			t.Errorf("missing %s %s: count=%d err=%v", kind, name, count, err)
		}
	}
}
