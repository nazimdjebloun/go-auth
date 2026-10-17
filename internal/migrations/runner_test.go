package migrations

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/schema"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	_ "modernc.org/sqlite"
)

func migrationDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestStandaloneFreshRepeatAndBorrowedSettings(t *testing.T) {
	db := migrationDB(t)
	if _, err := db.Exec("PRAGMA busy_timeout=1234"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		status, err := Apply(t.Context(), db, Options{Driver: "sqlite"})
		if err != nil {
			t.Fatal(err)
		}
		if status.Revision != 1 || len(status.History) != 1 || status.History[0].Mode != "executed" || status.Dirty {
			t.Fatalf("incorrect tracked state: %+v", status)
		}
		if err := Check(t.Context(), db, "sqlite"); err != nil {
			t.Fatal(err)
		}
	}
	var foreignKeys, busy int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatal(err)
	}
	if foreignKeys != 0 || busy != 1234 {
		t.Fatalf("caller settings changed: foreign_keys=%d busy_timeout=%d", foreignKeys, busy)
	}
	if err := db.PingContext(t.Context()); err != nil {
		t.Fatal("borrowed database was closed", err)
	}
}

func legacySchema(t *testing.T, db *sql.DB) {
	t.Helper()
	ddl, err := schema.For("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schema.SplitSQL(ddl) {
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExplicitAdoptionPreservesAuthDataAndHostReferences(t *testing.T) {
	db := migrationDB(t)
	legacySchema(t, db)
	for _, stmt := range []string{
		`INSERT INTO users(id,email,password_hash,password_pepper_version,created_at,updated_at)
		VALUES ('password-user','password@example.com','unchanged-hash',2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO users(id,email,created_at,updated_at)
		VALUES ('oauth-user','oauth@example.com',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`CREATE TABLE user_profiles(user_id TEXT PRIMARY KEY REFERENCES users(id), note TEXT)`,
		`INSERT INTO user_profiles VALUES ('password-user','unchanged')`,
		`INSERT INTO sessions(id,user_id,token_hash,is_revoked,created_at,last_active_at,expires_at)
		VALUES ('session','password-user','token-hash',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
		`INSERT INTO verification_tokens(id,user_id,email,token_hash,type,expires_at,used_at)
		VALUES ('verification','password-user','password@example.com','one-time-hash','reset_password',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Apply(t.Context(), db, Options{Driver: "sqlite"}); !errors.Is(err, ErrUntracked) {
		t.Fatalf("untracked auth tables were accepted: %v", err)
	}
	status, err := Adopt(t.Context(), db, Options{Driver: "sqlite"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if status.History[0].Mode != "adopted" {
		t.Fatal("executed creation SQL instead of recording adoption")
	}
	if _, err := Apply(t.Context(), db, Options{Driver: "sqlite"}); err != nil {
		t.Fatal(err)
	}
	var valid bool
	if err := db.QueryRow(`SELECT
		(SELECT password_hash='unchanged-hash' AND password_pepper_version=2 FROM users WHERE id='password-user')
		AND (SELECT password_hash IS NULL FROM users WHERE id='oauth-user')
		AND (SELECT is_revoked=1 AND token_hash='token-hash' FROM sessions WHERE id='session')
		AND (SELECT used_at IS NOT NULL AND token_hash='one-time-hash' FROM verification_tokens WHERE id='verification')
		AND (SELECT note='unchanged' FROM user_profiles WHERE user_id='password-user')`).Scan(&valid); err != nil || !valid {
		t.Fatalf("authentication state or host reference changed: %v", err)
	}
}

func TestAdoptionRejectsDriftWithoutCreatingHistory(t *testing.T) {
	db := migrationDB(t)
	legacySchema(t, db)
	if _, err := db.Exec("DROP INDEX idx_users_app_role"); err != nil {
		t.Fatal(err)
	}
	if _, err := Adopt(t.Context(), db, Options{Driver: "sqlite"}, 1); !errors.Is(err, ErrDrift) {
		t.Fatalf("drift was adopted: %v", err)
	}
	exists, err := objectExists(t.Context(), db, "sqlite", "goauth_migrations")
	if err != nil || exists {
		t.Fatal("failed adoption created metadata", err)
	}
}

func TestDirtyStateBlocksUntilVerifiedRepair(t *testing.T) {
	db := migrationDB(t)
	if _, err := Apply(t.Context(), db, Options{Driver: "sqlite"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE goauth_migrations SET state='started', completed_at=NULL"); err != nil {
		t.Fatal(err)
	}
	if err := Check(t.Context(), db, "sqlite"); !errors.Is(err, ErrDirty) {
		t.Fatalf("dirty startup was accepted: %v", err)
	}
	if _, err := Apply(t.Context(), db, Options{Driver: "sqlite"}); !errors.Is(err, ErrDirty) {
		t.Fatalf("dirty migration was retried: %v", err)
	}
	if _, err := db.Exec("DROP INDEX idx_users_app_role"); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairComplete(t.Context(), db, Options{Driver: "sqlite"}, 1); !errors.Is(err, ErrDrift) {
		t.Fatalf("incomplete schema was marked complete: %v", err)
	}
	if _, err := db.Exec("CREATE INDEX idx_users_app_role ON users(app_role_id,id)"); err != nil {
		t.Fatal(err)
	}
	if _, err := RepairComplete(t.Context(), db, Options{Driver: "sqlite"}, 1); err != nil {
		t.Fatal(err)
	}
	if err := Check(t.Context(), db, "sqlite"); err != nil {
		t.Fatal(err)
	}
}

func TestChecksumAndFutureHistoryAreRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
		want error
	}{
		{name: "checksum", sql: "UPDATE goauth_migrations SET checksum='modified'", want: ErrChecksum},
		{name: "future", sql: "UPDATE goauth_migrations SET migration_id=42", want: ErrUnknownHistory},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := migrationDB(t)
			if _, err := Apply(t.Context(), db, Options{Driver: "sqlite"}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(tc.sql); err != nil {
				t.Fatal(err)
			}
			if err := Check(t.Context(), db, "sqlite"); !errors.Is(err, tc.want) {
				t.Fatalf("untrusted history accepted: %v", err)
			}
		})
	}
}

func TestSQLiteLockWaitIsBounded(t *testing.T) {
	db := migrationDB(t)
	db.SetMaxOpenConns(2)
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), "ROLLBACK") }()
	_, err = Apply(t.Context(), db, Options{Driver: "sqlite", LockTimeout: 10 * time.Millisecond})
	if !errors.Is(err, ErrLockTimeout) {
		t.Fatalf("writer lock wait was not bounded: %v", err)
	}
}

func TestConcurrentStandaloneRunners(t *testing.T) {
	db := testdb.OpenSelected(t)
	other := testdb.SecondPool(t, db)
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, pool := range []*sql.DB{db, other} {
		go func() {
			<-start
			_, err := Apply(ctx, pool, Options{Driver: testdb.Driver(pool)})
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	status, err := Inspect(ctx, db, testdb.Driver(db))
	if err != nil || len(status.History) != 1 || status.Dirty {
		t.Fatalf("concurrent runners duplicated or corrupted history: %+v, %v", status, err)
	}
}

func TestSelectedBackendFailureState(t *testing.T) {
	db := testdb.OpenSelected(t)
	catalog, err := Load(testdb.Driver(db))
	if err != nil {
		t.Fatal(err)
	}
	options, err := (Options{Driver: catalog.Dialect}).defaults()
	if err != nil {
		t.Fatal(err)
	}
	l, err := acquire(t.Context(), db, catalog, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.conn.ExecContext(t.Context(), journalSQL(catalog.Dialect)); err != nil {
		_ = l.close(t.Context(), false)
		t.Fatal(err)
	}
	step := catalog.Migrations[0]
	step.statements = append(step.statements, "INSERT INTO missing_goauth_failure_table VALUES (1)")
	err = applyStep(t.Context(), l, catalog, step, options)
	if err == nil {
		_ = l.close(t.Context(), false)
		t.Fatal("injected execution failure succeeded")
	}
	if err := l.close(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if catalog.Dialect == "mysql" {
		status, err := Inspect(t.Context(), db, catalog.Dialect)
		if err != nil || !status.Dirty || status.Revision != 0 {
			t.Fatalf("partial MySQL DDL lost its dirty marker: %+v, %v", status, err)
		}
		if _, err := Apply(t.Context(), db, options); !errors.Is(err, ErrDirty) {
			t.Fatalf("partial DDL was replayed: %v", err)
		}
		// The injected failure follows all real SQL; verified repair is safe.
		if _, err := RepairComplete(t.Context(), db, options, step.ID); err != nil {
			t.Fatal(err)
		}
		return
	}
	exists, err := objectExists(t.Context(), db, catalog.Dialect, "users")
	if err != nil || exists {
		t.Fatal("transactional failure left auth DDL committed", err)
	}
	if _, err := Apply(t.Context(), db, options); err != nil {
		t.Fatal("rolled back migration could not be retried", err)
	}
}

func TestDataPostconditionMustBeTrue(t *testing.T) {
	db := migrationDB(t)
	legacySchema(t, db)
	catalog, err := Load("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	step := catalog.Migrations[0]
	step.Checks = []string{"SELECT FALSE"}
	if err := verifyStep(t.Context(), db, catalog, step, time.Second); err == nil {
		t.Fatal("failed data transformation was accepted")
	}
}

func TestSelectedBackendRejectsWeakenedForeignKeys(t *testing.T) {
	db := testdb.OpenSelected(t)
	db.SetMaxOpenConns(1)
	testdb.Apply(t, db)
	dialect := testdb.Driver(db)
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var weaken, restore string
	switch dialect {
	case "postgres":
		weaken = "ALTER TABLE users DROP CONSTRAINT users_app_role_id_fkey"
		restore = "ALTER TABLE users ADD CONSTRAINT users_app_role_id_fkey FOREIGN KEY (app_role_id) REFERENCES app_roles(id) ON DELETE RESTRICT NOT ENFORCED"
	case "mysql":
		weaken, restore = "SET SESSION foreign_key_checks=0", "SET SESSION foreign_key_checks=1"
	case "sqlite":
		weaken, restore = "PRAGMA foreign_keys=0", "PRAGMA foreign_keys=1"
	}
	if _, err := conn.ExecContext(t.Context(), weaken); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if dialect == "postgres" {
		if _, err := conn.ExecContext(t.Context(), restore); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
	}
	_, insertErr := conn.ExecContext(t.Context(), `INSERT INTO users(id,email,name,app_role_id,created_at,updated_at)
		VALUES ('11111111-1111-1111-1111-111111111111','orphan@example.com','','22222222-2222-2222-2222-222222222222',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
	if dialect != "postgres" {
		if _, err := conn.ExecContext(t.Context(), restore); err != nil {
			_ = conn.Close()
			t.Fatal(err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if insertErr != nil {
		t.Fatal(insertErr)
	}
	if _, err := Adopt(t.Context(), db, Options{Driver: dialect}, 1); !errors.Is(err, ErrDrift) {
		t.Fatalf("unenforced or orphaned auth FK was adopted: %v", err)
	}
	exists, err := objectExists(t.Context(), db, dialect, "goauth_migrations")
	if err != nil || exists {
		t.Fatal("invalid FK adoption initialized history", err)
	}
}

func TestStandaloneSelectedBackend(t *testing.T) {
	db := testdb.OpenSelected(t)
	dialect := testdb.Driver(db)
	for range 2 {
		if _, err := Apply(t.Context(), db, Options{Driver: dialect}); err != nil {
			t.Fatal(err)
		}
	}
	if err := Verify(t.Context(), db, Options{Driver: dialect}); err != nil {
		t.Fatal(err)
	}
	testdb.AssertSchema(t, db)
	testdb.AssertKeys(t, db)
	testdb.AssertForeignKeyIntegrity(t, db)
}
