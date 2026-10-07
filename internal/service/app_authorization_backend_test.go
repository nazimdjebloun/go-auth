package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

type appSQLAuditRecorder struct{ records *sqlstore.RecordRepository }

func (r appSQLAuditRecorder) Record(ctx context.Context, event audit.Event) error {
	return r.records.Insert(ctx, event)
}

func TestMySQL_AppAuthorizationRejectsRevokedSessionFromOldSnapshot(t *testing.T) {
	if testdb.Selected() != "mysql" {
		t.Skip("requires selected MySQL backend")
	}
	for _, action := range []string{"revoke", "delete", "remove_assurance"} {
		t.Run(action, func(t *testing.T) {
			f := newAppFixture(t)
			other := appSecondPool(t, f)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			session, err := f.s.sessionSvc.Create(ctx, api.CreateSessionInput{UserID: f.admin.UserID})
			if err != nil {
				t.Fatal(err)
			}
			f.s.config.RequireAdminTwoFactor = true
			f.s.config.Audit = appSQLAuditRecorder{sqlstore.NewRecordRepository(f.db)}
			if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", time.Now().UTC(), session.Session.ID); err != nil {
				t.Fatal(err)
			}
			revision, err := f.repo.AppStateRevision(ctx)
			if err != nil {
				t.Fatal(err)
			}
			want := error(domain.ErrSessionExpired)
			err = f.db.WithTx(ctx, func(txCtx context.Context) error {
				var isolation string
				if err := f.db.QueryRowContext(txCtx, "SELECT @@transaction_isolation").Scan(&isolation); err != nil {
					return err
				}
				if isolation != "REPEATABLE-READ" {
					return fmt.Errorf("test requires MySQL's default REPEATABLE-READ, got %s", isolation)
				}
				var revoked bool
				if err := f.db.QueryRowContext(txCtx, "SELECT is_revoked FROM sessions WHERE id=$1", session.Session.ID).Scan(&revoked); err != nil {
					return err
				}
				query := "UPDATE sessions SET is_revoked=true WHERE id=$1"
				switch action {
				case "delete":
					query, want = "DELETE FROM sessions WHERE id=$1", domain.ErrForbidden
				case "remove_assurance":
					query, want = "UPDATE sessions SET two_factor_verified_at=NULL WHERE id=$1", domain.ErrTwoFactorRequired
				}
				if _, err := other.db.ExecContext(ctx, query, session.Session.ID); err != nil {
					return err
				}
				_, err := f.s.CreatePermission(txCtx, api.CreateAppPermissionInput{
					Actor: api.AppPermissionActor{UserID: f.admin.UserID, SessionID: session.Session.ID},
					Key:   "app.snapshot.write", Name: "Must not be created",
				})
				return err
			})
			if !errors.Is(err, want) {
				t.Fatalf("old session snapshot authorized management: got %v, want %v", err, want)
			}
			permission, err := f.repo.PermissionByKey(ctx, "app.snapshot.write")
			if err != nil || permission != nil {
				t.Fatalf("denied operation left permission: %+v, %v", permission, err)
			}
			after, err := f.repo.AppStateRevision(ctx)
			if err != nil || after != revision {
				t.Fatalf("denied operation changed revision: %d/%d, %v", revision, after, err)
			}
			var count int
			if err := f.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log").Scan(&count); err != nil || count != 0 {
				t.Fatalf("denied operation left audit records: %d, %v", count, err)
			}
		})
	}
}

func TestMySQL_AppAuthorizationDeadlockRollsBackAcrossPools(t *testing.T) {
	if testdb.Selected() != "mysql" {
		t.Skip("requires selected MySQL backend")
	}
	testAppAuthorizationDeadlockRollsBackAcrossPools(t)
}

func TestPostgres_AppAuthorizationDeadlockRollsBackAcrossPools(t *testing.T) {
	if testdb.Selected() != "postgres" {
		t.Skip("requires selected PostgreSQL backend")
	}
	testAppAuthorizationDeadlockRollsBackAcrossPools(t)
}

func testAppAuthorizationDeadlockRollsBackAcrossPools(t *testing.T) {
	t.Helper()
	f := newAppFixture(t)
	other := appSecondPool(t, f)
	roles := []*domain.AppRole{f.role(t, "deadlock-a"), f.role(t, "deadlock-b")}
	pools := []*sqlstore.DB{f.db, other.db}
	repositories := []*sqlstore.AppPermissionsRepository{f.repo, other.repo}
	events := []audit.Event{
		audit.NewEvent(audit.EventAppRoleUpdated, audit.WithActor(f.admin.UserID)),
		audit.NewEvent(audit.EventAppRoleUpdated, audit.WithActor(f.admin.UserID)),
	}
	for _, pool := range pools {
		pool.SetMaxOpenConns(1)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	type outcome struct {
		index int
		err   error
	}
	results := make(chan outcome, 2)
	operation := func(index int) error {
		return pools[index].WithTx(ctx, func(txCtx context.Context) error {
			role := *roles[index]
			role.Name = "committed-" + role.Slug
			changed, err := repositories[index].UpdateAppRole(txCtx, &role, role.Revision)
			if err != nil {
				return err
			}
			if !changed {
				return domain.ErrAppAuthorizationConflict
			}
			now := time.Now().UTC()
			permission := &domain.AppPermission{
				ID: uuid.NewString(), Key: "app.deadlock." + string(rune('a'+index)),
				Name: "Transaction marker", IsEnabled: true, Revision: 1, CreatedAt: now, UpdatedAt: now,
			}
			if err := repositories[index].InsertAppPermission(txCtx, permission); err != nil {
				return err
			}
			if err := sqlstore.NewRecordRepository(pools[index]).Insert(txCtx, events[index]); err != nil {
				return err
			}
			ready <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			// Opposite role order deliberately forces a real engine deadlock.
			// Production management takes users then state in a common order.
			_, err = repositories[index].RoleByID(txCtx, roles[1-index].ID)
			return err
		})
	}
	for index := range 2 {
		wg.Go(func() { results <- outcome{index: index, err: operation(index)} })
	}
	for range 2 {
		select {
		case <-ready:
		case result := <-results:
			t.Fatalf("transaction failed before deadlock barrier: %v", result.err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	close(release)
	winner, victim := -1, -1
	for range 2 {
		result := <-results
		if result.err == nil {
			if winner != -1 {
				t.Fatal("forced deadlock allowed both commits")
			}
			winner = result.index
			continue
		}
		var mysqlErr *mysql.MySQLError
		var postgresErr *pgconn.PgError
		mysqlDeadlock := errors.As(result.err, &mysqlErr) && mysqlErr.Number == 1213
		postgresDeadlock := errors.As(result.err, &postgresErr) && postgresErr.Code == "40P01"
		if !mysqlDeadlock && !postgresDeadlock {
			t.Fatalf("expected native deadlock, got %v", result.err)
		}
		victim = result.index
	}
	if winner == -1 || victim == -1 {
		t.Fatalf("expected one commit and one deadlock: winner=%d victim=%d", winner, victim)
	}
	for index, before := range roles {
		after, err := f.repo.RoleByID(ctx, before.ID)
		if err != nil {
			t.Fatal(err)
		}
		wantRevision, wantName, wantCount := before.Revision, before.Name, 0
		if index == winner {
			wantRevision, wantName, wantCount = before.Revision+1, "committed-"+before.Slug, 1
		}
		if after.Revision != wantRevision || after.Name != wantName {
			t.Fatalf("partial role commit: %+v, wanted revision=%d name=%s", after, wantRevision, wantName)
		}
		key := "app.deadlock." + string(rune('a'+index))
		permission, err := f.repo.PermissionByKey(ctx, key)
		if err != nil || (permission != nil) != (index == winner) {
			t.Fatalf("partial definition commit: %+v, %v", permission, err)
		}
		var count int
		if err := f.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE id=$1", events[index].ID).Scan(&count); err != nil || count != wantCount {
			t.Fatalf("partial audit commit: count=%d wanted=%d, %v", count, wantCount, err)
		}
		if pools[index].Stats().InUse != 0 {
			t.Fatal("deadlock pinned a pooled transaction")
		}
		if err := pools[index].PingContext(ctx); err != nil {
			t.Fatalf("connection not reusable: %v", err)
		}
	}
	// The victim's entire operation succeeds in a new transaction; no partial
	// writes or retained locks obstruct retry, and the audit ID remains reusable.
	if err := operation(victim); err != nil {
		t.Fatalf("whole-operation retry failed: %v", err)
	}
	after, err := f.repo.RoleByID(ctx, roles[victim].ID)
	if err != nil || after.Revision != roles[victim].Revision+1 {
		t.Fatalf("retry revision: %+v, %v", after, err)
	}
	permission, err := f.repo.PermissionByKey(ctx, "app.deadlock."+string(rune('a'+victim)))
	if err != nil || permission == nil {
		t.Fatalf("retry did not commit permission: %+v, %v", permission, err)
	}
	var count int
	if err := f.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM audit_log WHERE id=$1", events[victim].ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retry did not commit exactly one audit record: %d, %v", count, err)
	}
}
