package integration_test

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// Wait for persisted events, not a guessed number of worker timer ticks.
func waitAuditCount(t *testing.T, db *sql.DB, query string, want int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var got int
		if err := db.QueryRowContext(ctx, query).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got >= want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("audit persistence: got %d events, want %d: %v", got, want, ctx.Err())
		case <-ticker.C:
		}
	}
}
