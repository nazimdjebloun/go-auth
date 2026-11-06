package migrations

import (
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

func TestRedisUpgradePreservesPopulatedCredentials(t *testing.T) {
	driver := testdb.Selected()
	catalog, err := Load(driver)
	if err != nil {
		t.Fatal(err)
	}
	db := testdb.OpenSelected(t)
	opts := Options{Driver: driver}
	prefix := catalogPrefix(t, files, catalog, 4)
	if _, err = runCatalog(t.Context(), db, opts, prefix, "apply", 0); err != nil {
		t.Fatal(err)
	}
	store := sqlstore.NewDB(db, driver)
	now := time.Now().UTC().Truncate(time.Second)
	user := "00000000-0000-4000-8000-000000000001"
	sid := "00000000-0000-4000-8000-000000000002"
	tid := "00000000-0000-4000-8000-000000000003"
	if _, err = store.ExecContext(t.Context(), "INSERT INTO users (id,email,name,role,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6)", user, "redis-upgrade@example.test", "Existing", "user", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ExecContext(t.Context(), "INSERT INTO sessions (id,user_id,token_hash,refresh_token_hash,prev_refresh_token_hash,created_at,last_active_at,expires_at,refresh_expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", sid, user, "access-hash", "refresh-hash", "previous-hash", now, now, now.Add(time.Hour), now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.ExecContext(t.Context(), "INSERT INTO verification_tokens (id,user_id,email,token_hash,type,created_at,expires_at,attempts,resend_count,used_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", tid, user, "redis-upgrade@example.test", "proof-hash", "2fa_login", now, now.Add(time.Hour), 2, 1, now); err != nil {
		t.Fatal(err)
	}
	if _, err = Apply(t.Context(), db, opts); err != nil {
		t.Fatal(err)
	}
	if err = Verify(t.Context(), db, opts); err != nil {
		t.Fatal(err)
	}
	var version string
	for _, table := range []string{"sessions", "verification_tokens"} {
		id := sid
		if table == "verification_tokens" {
			id = tid
		}
		if err = store.QueryRowContext(t.Context(), "SELECT cache_version FROM "+table+" WHERE id=$1", id).Scan(&version); err != nil || version != "legacy" {
			t.Fatalf("backfill %s: %s %v", table, version, err)
		}
	}
	s, e := sqlstore.NewSessionRepository(store).GetByTokenHash(t.Context(), "access-hash")
	if e != nil || s == nil || s.RefreshTokenHash != "refresh-hash" || s.PreviousRefreshHash != "previous-hash" {
		t.Fatal("session changed", e)
	}
	tok, e := sqlstore.NewTokenRepository(store).GetByID(t.Context(), tid)
	if e != nil || tok == nil || tok.TokenHash != "proof-hash" || tok.Attempts != 2 || tok.ResendCount != 1 || tok.UsedAt == nil {
		t.Fatal("proof changed", e)
	}
	if _, err = Apply(t.Context(), db, opts); err != nil {
		t.Fatal("repeat migration", err)
	}
}
