package goauth

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestSQLiteSessionForeignKey(t *testing.T) {
	ctx := context.Background()
	cfg := &Config{app: AppConfig{Database: DatabaseConfig{Driver: DriverSQLite, URL: filepath.Join(t.TempDir(), "auth.db")}}}
	_, db, err := openDatabase(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ddl, err := GetSchema("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range SplitSQL(ddl) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	_, err = db.ExecContext(ctx, `INSERT INTO sessions
		(id, user_id, token_hash, expires_at, created_at, last_active_at)
		VALUES ('session', 'missing-user', 'hash', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`)
	if err == nil || !strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
		t.Fatalf("expected foreign-key rejection, got %v", err)
	}
}
