package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

func newAdminGuardDB(t *testing.T) (*DB, *DB) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "guard.db") + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	open := func() *DB {
		raw, err := sql.Open("sqlite", dsn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := raw.Close(); err != nil {
				t.Error(err)
			}
		})
		return NewDB(raw, "sqlite")
	}
	a, b := open(), open()
	if _, err := a.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY,role TEXT,is_banned BOOLEAN,banned_at DATETIME,updated_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func seedGuardUser(t *testing.T, db *DB, id string, role domain.Role, banned bool) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO users VALUES (?,?,?,NULL,CURRENT_TIMESTAMP)`, id, role, banned); err != nil {
		t.Fatal(err)
	}
}

func guardMutation(ctx context.Context, r *UserRepository, op, id string) (bool, error) {
	now := time.Now().UTC()
	switch op {
	case "delete":
		return r.DeleteWithAdminGuard(ctx, id)
	case "ban":
		return r.BanWithAdminGuard(ctx, id, true, &now, now)
	default:
		return r.DemoteWithAdminGuard(ctx, id, domain.RoleUser, now)
	}
}

func TestAdminGuard_LastUsableAdmin(t *testing.T) {
	for _, op := range []string{"delete", "ban", "demote"} {
		t.Run(op, func(t *testing.T) {
			db, _ := newAdminGuardDB(t)
			seedGuardUser(t, db, "active", domain.RoleAdmin, false)
			seedGuardUser(t, db, "banned", domain.RoleAdmin, true)
			r := NewUserRepository(db)
			changed, err := guardMutation(context.Background(), r, op, "active")
			if err != nil || changed {
				t.Fatalf("last usable admin: changed=%v err=%v", changed, err)
			}
			changed, err = guardMutation(context.Background(), r, op, "banned")
			if err != nil || !changed {
				t.Fatalf("already banned admin: changed=%v err=%v", changed, err)
			}
			_, err = guardMutation(context.Background(), r, op, "missing")
			if !errors.Is(err, domain.ErrUserNotFound) {
				t.Fatalf("missing user: %v", err)
			}
		})
	}
}

func TestAdminGuard_ConcurrentReductionsAcrossPools(t *testing.T) {
	for _, pair := range [][2]string{{"delete", "delete"}, {"ban", "ban"}, {"demote", "demote"}, {"delete", "ban"}, {"ban", "demote"}, {"demote", "delete"}} {
		t.Run(pair[0]+"_"+pair[1], func(t *testing.T) {
			a, b := newAdminGuardDB(t)
			seedGuardUser(t, a, "a", domain.RoleAdmin, false)
			seedGuardUser(t, a, "b", domain.RoleAdmin, false)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			start := make(chan struct{})
			type outcome struct {
				changed bool
				err     error
			}
			results := make(chan outcome, 2)
			for i, db := range []*DB{a, b} {
				go func(i int, db *DB) {
					<-start
					changed, err := guardMutation(ctx, NewUserRepository(db), pair[i], []string{"a", "b"}[i])
					results <- outcome{changed, err}
				}(i, db)
			}
			close(start)
			wins := 0
			for range 2 {
				select {
				case result := <-results:
					if result.err != nil {
						t.Fatal(result.err)
					}
					if result.changed {
						wins++
					}
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if wins != 1 {
				t.Fatalf("successful reductions=%d, want 1", wins)
			}
			var count int
			if err := a.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin' AND is_banned=false`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 1 {
				t.Fatalf("usable admins=%d, want 1", count)
			}
		})
	}
}

func TestAdminGuard_OuterRollbackAndPanic(t *testing.T) {
	for _, panicCase := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panicCase], func(t *testing.T) {
			db, _ := newAdminGuardDB(t)
			seedGuardUser(t, db, "a", domain.RoleAdmin, false)
			seedGuardUser(t, db, "b", domain.RoleAdmin, false)
			r := NewUserRepository(db)
			sentinel := errors.New("rollback")
			func() {
				if panicCase {
					defer func() {
						if recover() != sentinel {
							t.Error("panic not propagated")
						}
					}()
				}
				err := db.WithTx(context.Background(), func(ctx context.Context) error {
					changed, err := r.DeleteWithAdminGuard(ctx, "a")
					if err != nil {
						return err
					}
					if !changed {
						t.Fatal("delete blocked")
					}
					if panicCase {
						panic(sentinel)
					}
					return sentinel
				})
				if !errors.Is(err, sentinel) {
					t.Fatalf("got %v", err)
				}
			}()
			var count int
			if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 2 {
				t.Fatalf("rollback left %d users", count)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := r.WithAdminGuard(ctx, func(context.Context) error { return nil }); err != nil {
				t.Fatalf("lock leaked: %v", err)
			}
		})
	}
}
