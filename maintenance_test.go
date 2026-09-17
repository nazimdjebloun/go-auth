package goauth

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
)

var errMaintenanceTest = errors.New("maintenance target failed")

// fakeDeleter records what the runner passed it and returns canned results,
// so runner behavior is testable without a database.
type fakeDeleter struct {
	deleted int
	err     error
	cutoff  time.Time
	limit   int
}

func (f *fakeDeleter) DeleteExpiredBatch(_ context.Context, cutoff time.Time, limit int) (int, error) {
	f.cutoff = cutoff
	f.limit = limit
	if f.err != nil {
		return 0, f.err
	}
	return f.deleted, nil
}

// newMaintenanceTestDB opens a migrated SQLite database with one seeded user,
// returning the handle plus both maintenance-capable repositories.
func newMaintenanceTestDB(t *testing.T) (*sqlstore.DB, *sqlstore.SessionRepository, *sqlstore.TokenRepository) {
	t.Helper()
	ctx := context.Background()
	cfg := &Config{app: AppConfig{Database: DatabaseConfig{Driver: DriverSQLite, URL: filepath.Join(t.TempDir(), "auth.db")}}}
	_, db, err := openDatabase(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	ddl, err := GetSchema("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range SplitSQL(ddl) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO users
		(id, email, name, role, is_verified, is_banned, two_factor_enabled, org_owner_count, created_at, updated_at)
		VALUES ('u1', 'janitor@example.com', 'Janitor', 'user', 1, 0, 0, 0, $1, $2)`, now, now); err != nil {
		t.Fatal(err)
	}

	return db, sqlstore.NewSessionRepository(db), sqlstore.NewTokenRepository(db)
}

func insertMaintenanceSession(t *testing.T, ctx context.Context, db *sqlstore.DB, id string, expiresAt, refreshExpiresAt time.Time) {
	t.Helper()
	_, err := db.ExecContext(ctx, `INSERT INTO sessions
		(id, user_id, token_hash, refresh_token_hash, prev_refresh_token_hash, ip_address, user_agent, is_revoked, expires_at, refresh_expires_at, created_at, last_active_at)
		VALUES ($1, 'u1', $2, $3, '', '127.0.0.1', 'test-agent', 0, $4, $5, $6, $7)`,
		id, "tok-"+id, "ref-"+id, expiresAt, refreshExpiresAt, time.Now().UTC(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
}

func insertMaintenanceToken(t *testing.T, ctx context.Context, db *sqlstore.DB, id string, expiresAt time.Time) {
	t.Helper()
	_, err := db.ExecContext(ctx, `INSERT INTO verification_tokens
		(id, user_id, email, token_hash, type, expires_at) VALUES ($1, 'u1', 'janitor@example.com', $2, 'password_reset', $3)`,
		id, "tok-"+id, expiresAt)
	if err != nil {
		t.Fatal(err)
	}
}

func rowExists(t *testing.T, ctx context.Context, db *sqlstore.DB, table, id string) bool {
	t.Helper()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

// TestDeleteExpiredBatch_SessionsOnlyWhenFullyDead pins the conservative
// rule: a session is only removed once it is dead on both clocks. A session
// whose own expiry passed while its refresh token is still live must survive,
// because deleting it would end a login the library still considers valid.
func TestDeleteExpiredBatch_SessionsOnlyWhenFullyDead(t *testing.T) {
	ctx := context.Background()
	db, sessions, _ := newMaintenanceTestDB(t)
	now := time.Now().UTC()

	insertMaintenanceSession(t, ctx, db, "fully-expired", now.Add(-48*time.Hour), now.Add(-48*time.Hour))
	insertMaintenanceSession(t, ctx, db, "refresh-still-live", now.Add(-48*time.Hour), now.Add(24*time.Hour))
	insertMaintenanceSession(t, ctx, db, "live", now.Add(24*time.Hour), now.Add(24*time.Hour))

	n, err := sessions.DeleteExpiredBatch(ctx, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted %d sessions, want 1", n)
	}
	if rowExists(t, ctx, db, "sessions", "fully-expired") {
		t.Error("fully expired session survived cleanup")
	}
	if !rowExists(t, ctx, db, "sessions", "refresh-still-live") {
		t.Error("session with a live refresh token was deleted")
	}
	if !rowExists(t, ctx, db, "sessions", "live") {
		t.Error("live session was deleted")
	}
}

func TestDeleteExpiredBatch_RespectsBatchLimit(t *testing.T) {
	ctx := context.Background()
	db, sessions, _ := newMaintenanceTestDB(t)
	now := time.Now().UTC()

	for _, id := range []string{"e1", "e2", "e3"} {
		insertMaintenanceSession(t, ctx, db, id, now.Add(-72*time.Hour), now.Add(-72*time.Hour))
	}

	n, err := sessions.DeleteExpiredBatch(ctx, now, 2)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("deleted %d sessions, want 2 (batch limit)", n)
	}

	remaining := 0
	for _, id := range []string{"e1", "e2", "e3"} {
		if rowExists(t, ctx, db, "sessions", id) {
			remaining++
		}
	}
	if remaining != 1 {
		t.Fatalf("%d sessions remain, want exactly 1 for the next pass", remaining)
	}
}

func TestDeleteExpiredBatch_Tokens(t *testing.T) {
	ctx := context.Background()
	db, _, tokens := newMaintenanceTestDB(t)
	now := time.Now().UTC()

	insertMaintenanceToken(t, ctx, db, "expired-token", now.Add(-2*time.Hour))
	insertMaintenanceToken(t, ctx, db, "live-token", now.Add(2*time.Hour))

	n, err := tokens.DeleteExpiredBatch(ctx, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("deleted %d tokens, want 1", n)
	}
	if rowExists(t, ctx, db, "verification_tokens", "expired-token") {
		t.Error("expired token survived cleanup")
	}
	if !rowExists(t, ctx, db, "verification_tokens", "live-token") {
		t.Error("live token was deleted")
	}
}

func TestDeleteExpiredBatch_RejectsNonPositiveLimit(t *testing.T) {
	ctx := context.Background()
	_, sessions, _ := newMaintenanceTestDB(t)
	if _, err := sessions.DeleteExpiredBatch(ctx, time.Now().UTC(), 0); err == nil {
		t.Fatal("expected an error for a non-positive batch limit")
	}
}

// TestMaintenanceRunner_RunPass exercises the runner directly, including the
// fail-soft contract: one target erroring must not stop the others.
func TestMaintenanceRunner_RunPass(t *testing.T) {
	failing := &fakeDeleter{err: errMaintenanceTest}
	working := &fakeDeleter{deleted: 3}
	runner := newMaintenanceRunner(MaintenanceConfig{BatchSize: 10}, []maintenanceTarget{
		{name: "broken", deleter: failing, record: func(r *MaintenanceResult, n int) { r.SessionsDeleted = n }},
		{name: "working", deleter: working, record: func(r *MaintenanceResult, n int) { r.TokensDeleted = n }},
	})

	result := runner.runPass(context.Background())
	if result.SessionsDeleted != 0 {
		t.Errorf("failing target recorded %d", result.SessionsDeleted)
	}
	if result.TokensDeleted != 3 {
		t.Errorf("working target recorded %d, want 3", result.TokensDeleted)
	}
	if working.limit != 10 {
		t.Errorf("batch size %d passed to target, want 10", working.limit)
	}
	if !working.cutoff.Before(time.Now().UTC()) {
		t.Error("cutoff was not set in the past")
	}
}

func TestMaintenanceConfig_NegativeValuesRejected(t *testing.T) {
	base := func() []Option {
		return []Option{
			WithApp(AppConfig{
				Name:     "TestApp",
				BaseURL:  "http://localhost:3000",
				Database: DatabaseConfig{Driver: DriverSQLite, URL: "file:x.db"},
			}),
			WithSecret(strings.Repeat("a", 32)),
			WithSecurity(SecurityConfig{AllowedOrigins: []string{"http://localhost:3000"}}),
			// Admin-login 2FA is on by default and needs a mailer; opt out so
			// these cases fail only on maintenance validation.
			WithTwoFactor(TwoFactorConfig{DisableAdminTwoFactor: true}),
		}
	}

	for _, tc := range []struct {
		name string
		cfg  MaintenanceConfig
		want string
	}{
		{"negative interval", MaintenanceConfig{Interval: -time.Hour}, "interval"},
		{"negative batch size", MaintenanceConfig{BatchSize: -1}, "batch_size"},
		{"negative grace", MaintenanceConfig{Grace: -time.Minute}, "grace"},
		{"negative timeout", MaintenanceConfig{Timeout: -time.Second}, "timeout"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := append(base(), WithMaintenance(tc.cfg))
			if _, err := NewConfig(opts...); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("NewConfig error = %v, want one mentioning %q", err, tc.want)
			}
		})
	}

	// Zero means "use the documented defaults" and must stay valid.
	opts := append(base(), WithMaintenance(MaintenanceConfig{}))
	if _, err := NewConfig(opts...); err != nil {
		t.Fatalf("zero-valued MaintenanceConfig rejected: %v", err)
	}
}

func TestMaintenanceConfig_WithDefaults(t *testing.T) {
	got := MaintenanceConfig{}.withDefaults()
	if got.Interval != DefaultMaintenanceInterval ||
		got.BatchSize != DefaultMaintenanceBatchSize ||
		got.Grace != DefaultMaintenanceGrace ||
		got.Timeout != DefaultMaintenanceTimeout {
		t.Fatalf("defaults not applied: %+v", got)
	}
	if got.Logger == nil {
		t.Error("logger default missing")
	}
}
