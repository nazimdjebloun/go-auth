package sqlstore

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// providerAccountsFixture creates the columns the provider-account queries
// read or write. Timestamps are NOT NULL because ListByUserID scans them
// into time.Time values.
func providerAccountsFixture(t *testing.T, db *DB) {
	t.Helper()
	if _, err := db.Exec(`
		CREATE TABLE provider_accounts (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			provider_user_id TEXT NOT NULL,
			provider_email TEXT NOT NULL DEFAULT '',
			provider_name TEXT NOT NULL DEFAULT '',
			avatar_url TEXT NOT NULL DEFAULT '',
			access_token TEXT,
			refresh_token TEXT,
			token_expires_at DATETIME,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`); err != nil {
		t.Fatal(err)
	}
}

func seedProviderAccount(t *testing.T, db *DB, id, userID, provider string) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := db.Exec(`
		INSERT INTO provider_accounts (id, user_id, provider, provider_user_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, userID, provider, provider+"-uid", now, now); err != nil {
		t.Fatal(err)
	}
}

func countProviderAccounts(t *testing.T, db *DB, userID string) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM provider_accounts WHERE user_id = ?", userID,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLockByUserID_LeavesDataIntact(t *testing.T) {
	db := newSQLiteTestDB(t)
	providerAccountsFixture(t, db)
	seedProviderAccount(t, db, "pa-1", "u1", "google")
	seedProviderAccount(t, db, "pa-2", "u1", "github")
	repo := NewProviderAccountRepository(db)

	if err := repo.LockByUserID(context.Background(), "u1"); err != nil {
		t.Fatal(err)
	}
	if n := countProviderAccounts(t, db, "u1"); n != 2 {
		t.Fatalf("lock changed the provider set: %d rows, want 2", n)
	}
}

// TestLockByUserID_SerializesConcurrentUnlinks is the regression test for
// the last-provider unlink race: two requests that both observe two linked
// providers must not both delete. The first transaction takes the provider
// rows' write locks and holds them across an artificial delay; the second
// request's lock must block until the first commits, so its subsequent
// count observes the post-delete set (1) instead of the stale pre-delete
// set (2). If the lock ever stops serializing, the second request sails
// straight through and observes 2 — the same broken interleaving the Unlink
// guard relies on never seeing again.
func TestLockByUserID_SerializesConcurrentUnlinks(t *testing.T) {
	db := newSQLiteTestDB(t)
	providerAccountsFixture(t, db)
	seedProviderAccount(t, db, "pa-1", "u1", "google")
	seedProviderAccount(t, db, "pa-2", "u1", "github")
	repo := NewProviderAccountRepository(db)

	locked := make(chan struct{})
	done := make(chan struct{})
	var secondObservedCount int32 = -1
	var secondWaited atomic.Bool

	// First unlink: lock, delete one provider, and hold the locks across a
	// delay so the second request has every opportunity to race through.
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_ = db.WithTx(context.Background(), func(txCtx context.Context) error {
			if err := repo.LockByUserID(txCtx, "u1"); err != nil {
				t.Error(err)
				return err
			}
			close(locked)
			if err := repo.Delete(txCtx, "u1", "google"); err != nil {
				t.Error(err)
				return err
			}
			time.Sleep(300 * time.Millisecond)
			return nil
		})
	}()

	// Second unlink: must wait for the first transaction's locks before its
	// lock even returns, then observe the post-delete provider set.
	<-locked
	time.Sleep(50 * time.Millisecond) // let the first tx settle into its delay
	lockStart := time.Now()
	go func() {
		defer close(done)
		_ = db.WithTx(context.Background(), func(txCtx context.Context) error {
			if err := repo.LockByUserID(txCtx, "u1"); err != nil {
				t.Error(err)
				return err
			}
			if time.Since(lockStart) > 150*time.Millisecond {
				secondWaited.Store(true)
			}
			accounts, err := repo.ListByUserID(txCtx, "u1")
			if err != nil {
				t.Error(err)
				return err
			}
			atomic.StoreInt32(&secondObservedCount, int32(len(accounts)))
			return nil
		})
	}()
	<-done
	<-firstDone

	if !secondWaited.Load() {
		t.Error("second unlink did not block on the first transaction's locks")
	}
	if got := atomic.LoadInt32(&secondObservedCount); got != 1 {
		t.Fatalf("second unlink observed %d providers, want 1 (post-delete state)", got)
	}
	if n := countProviderAccounts(t, db, "u1"); n != 1 {
		t.Fatalf("provider rows = %d, want 1", n)
	}
}
