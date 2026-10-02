package service

import (
	"context"
	"errors"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
)

func deletionExec(t *testing.T, f *passwordTransactionFixture, query string, args ...any) {
	t.Helper()
	if strings.HasPrefix(query, "CREATE TRIGGER ") {
		fields := strings.Fields(query)
		operation := fields[4]
		table := fields[6]
		if operation == "UPDATE" {
			table = fields[8]
		}
		testdb.FailWrites(t, f.db.DB, fields[2], table, operation, "")
		return
	}
	if _, err := f.db.ExecContext(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}

func deletionCount(t *testing.T, f *passwordTransactionFixture, query string, want int) {
	t.Helper()
	var got int
	if err := f.db.QueryRowContext(context.Background(), query).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s: got %d, want %d", query, got, want)
	}
}

func deletionCoordinator(f *passwordTransactionFixture) *AccountDeletion {
	return NewAccountDeletion(f.db, sqlstore.NewOrgRepository(f.db), f.sessions, f.users)
}

func seedDeletionOrg(t *testing.T, f *passwordTransactionFixture, id string, owners int) {
	t.Helper()
	// A second member is not an administrator; owner counts are independent.
	deletionExec(t, f, `INSERT INTO users (id,email,name,created_at,updated_at) VALUES ('00000000-0000-4000-8000-000000000090','other@example.com','Other',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`)
	deletionExec(t, f, `INSERT INTO organizations (id,name,slug,owner_count,member_count,created_at,updated_at) VALUES ($1,$2,$3,$4,2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, id, id, id, owners)
	deletionExec(t, f, `INSERT INTO organization_members VALUES ($1,$2,'owner',CURRENT_TIMESTAMP)`, id, f.userID)
	role := "member"
	if owners == 2 {
		role = "owner"
	}
	deletionExec(t, f, `INSERT INTO organization_members VALUES ($1,'00000000-0000-4000-8000-000000000090',$2,CURRENT_TIMESTAMP)`, id, role)
	deletionExec(t, f, `UPDATE users SET org_owner_count=org_owner_count+1 WHERE id=$1`, f.userID)
	if owners == 2 {
		deletionExec(t, f, `UPDATE users SET org_owner_count=org_owner_count+1 WHERE id='00000000-0000-4000-8000-000000000090'`)
	}
}

func assertDeletionRolledBack(t *testing.T, f *passwordTransactionFixture, owners int) {
	t.Helper()
	user, err := f.users.GetByID(context.Background(), f.userID)
	if err != nil || user == nil {
		t.Fatalf("user not restored: %v", err)
	}
	if user.OrgOwnerCount != 1 {
		t.Fatalf("user owner count = %d, want 1", user.OrgOwnerCount)
	}
	session, err := f.sessions.GetByTokenHash(context.Background(), f.session)
	if err != nil || session == nil {
		t.Fatalf("session not restored: %v", err)
	}
	token, err := f.tokens.GetByID(context.Background(), f.tokenID)
	if err != nil || token == nil || token.UsedAt != nil {
		t.Fatalf("token not restored unused: %+v / %v", token, err)
	}
	deletionCount(t, f, "SELECT member_count FROM organizations WHERE id='00000000-0000-4000-8000-000000000091'", 2)
	deletionCount(t, f, "SELECT owner_count FROM organizations WHERE id='00000000-0000-4000-8000-000000000091'", owners)
	deletionCount(t, f, "SELECT COUNT(*) FROM organization_members WHERE org_id='00000000-0000-4000-8000-000000000091'", 2)
}

func TestAccountDeletion_RollbackMatrix(t *testing.T) {
	for _, tc := range []struct {
		name, setup string
		owners      int
		want        error
	}{
		{name: "last owner", owners: 1, want: domain.ErrCannotRemoveLastOwner},
		{name: "last usable admin", owners: 2, setup: `UPDATE users SET role='admin' WHERE id='00000000-0000-4000-8000-000000000010'`, want: domain.ErrCannotDeleteLastAdmin},
		{name: "counter write", owners: 2, setup: `CREATE TRIGGER fail_delete BEFORE UPDATE OF member_count ON organizations BEGIN SELECT RAISE(ABORT,'injected rollback'); END`},
		{name: "session delete", owners: 2, setup: `CREATE TRIGGER fail_delete BEFORE DELETE ON sessions BEGIN SELECT RAISE(ABORT,'injected rollback'); END`},
		{name: "user delete after counters and sessions", owners: 2, setup: `CREATE TRIGGER fail_delete BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'injected rollback'); END`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			seedDeletionOrg(t, f, "00000000-0000-4000-8000-000000000091", tc.owners)
			if tc.setup != "" {
				deletionExec(t, f, tc.setup)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := deletionCoordinator(f).DeleteUser(ctx, f.userID)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("got %v, want %v", err, tc.want)
				}
			} else if err == nil || !strings.Contains(err.Error(), "injected failure") {
				t.Fatalf("wanted injected failure, got %v", err)
			}
			assertDeletionRolledBack(t, f, tc.owners)
		})
	}
}

func TestAccountDeletion_SuccessAndRepeatedDelete(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	seedDeletionOrg(t, f, "00000000-0000-4000-8000-000000000091", 2)
	d := deletionCoordinator(f)
	if err := d.DeleteUser(context.Background(), f.userID); err != nil {
		t.Fatal(err)
	}
	deletionCount(t, f, "SELECT COUNT(*) FROM users WHERE id='00000000-0000-4000-8000-000000000010'", 0)
	deletionCount(t, f, "SELECT COUNT(*) FROM sessions", 0)
	deletionCount(t, f, "SELECT COUNT(*) FROM verification_tokens", 0)
	deletionCount(t, f, "SELECT member_count FROM organizations WHERE id='00000000-0000-4000-8000-000000000091'", 1)
	deletionCount(t, f, "SELECT owner_count FROM organizations WHERE id='00000000-0000-4000-8000-000000000091'", 1)
	deletionCount(t, f, "SELECT org_owner_count FROM users WHERE id='00000000-0000-4000-8000-000000000090'", 1)
	if err := d.DeleteUser(context.Background(), f.userID); !errors.Is(err, domain.ErrUserNotFound) {
		t.Fatalf("repeat delete = %v", err)
	}
	deletionCount(t, f, "SELECT member_count FROM organizations WHERE id='00000000-0000-4000-8000-000000000091'", 1)
}
