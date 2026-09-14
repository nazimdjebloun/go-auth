package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func createOrgMembersTable(t *testing.T, db *DB) {
	t.Helper()
	if _, err := db.Exec(`
		CREATE TABLE organization_members (
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL,
			joined_at DATETIME NOT NULL
		)`); err != nil {
		t.Fatal(err)
	}
}

func seedOrgMember(t *testing.T, db *DB, orgID, userID string, role domain.OrgRole) {
	t.Helper()
	if _, err := db.Exec(
		"INSERT INTO organization_members (org_id, user_id, role, joined_at) VALUES (?, ?, ?, ?)",
		orgID, userID, string(role), time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
}

func orgMemberRole(t *testing.T, db *DB, orgID, userID string) (string, bool) {
	t.Helper()
	var role string
	err := db.QueryRowContext(context.Background(),
		"SELECT role FROM organization_members WHERE org_id = ? AND user_id = ?", orgID, userID,
	).Scan(&role)
	if err != nil {
		return "", false
	}
	return role, true
}

func TestRemoveMember_RequiresExpectedRole(t *testing.T) {
	db := newSQLiteTestDB(t)
	createOrgMembersTable(t, db)
	seedOrgMember(t, db, "o1", "u1", domain.OrgRoleOwner)
	repo := NewOrgRepository(db)
	ctx := context.Background()

	// A delete asserting the wrong role must touch nothing: without the
	// role predicate in the statement, a removal that read "owner" before a
	// concurrent demote would corrupt the denormalized owner counts.
	removed, err := repo.RemoveMember(ctx, "o1", "u1", domain.OrgRoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("remove with a stale role must not delete the row")
	}
	if role, ok := orgMemberRole(t, db, "o1", "u1"); !ok || role != "owner" {
		t.Fatalf("row changed by a failed guarded delete: role=%q present=%v", role, ok)
	}

	removed, err = repo.RemoveMember(ctx, "o1", "u1", domain.OrgRoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	if !removed {
		t.Fatal("remove with the current role did not delete the row")
	}
	if _, ok := orgMemberRole(t, db, "o1", "u1"); ok {
		t.Fatal("membership row still present after guarded delete")
	}

	// Deleting an already-gone membership reports no match, so callers can
	// roll back rather than decrement counts twice.
	removed, err = repo.RemoveMember(ctx, "o1", "u1", domain.OrgRoleOwner)
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Fatal("repeat delete reported a removal")
	}
}

func TestUpdateMemberRole_RequiresExpectedRole(t *testing.T) {
	db := newSQLiteTestDB(t)
	createOrgMembersTable(t, db)
	seedOrgMember(t, db, "o1", "u1", domain.OrgRoleMember)
	repo := NewOrgRepository(db)
	ctx := context.Background()

	// A concurrent promotion already happened: the stale owner-conditional
	// update must not land on top of it.
	updated, err := repo.UpdateMemberRole(ctx, "o1", "u1", domain.OrgRoleOwner, domain.OrgRoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Fatal("role update with a stale expected role must not apply")
	}
	if role, ok := orgMemberRole(t, db, "o1", "u1"); !ok || role != "member" {
		t.Fatalf("row changed by a failed guarded update: role=%q present=%v", role, ok)
	}

	updated, err = repo.UpdateMemberRole(ctx, "o1", "u1", domain.OrgRoleMember, domain.OrgRoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("role update with the current role did not apply")
	}
	if role, ok := orgMemberRole(t, db, "o1", "u1"); !ok || role != "admin" {
		t.Fatalf("role = %q present=%v, want admin/true", role, ok)
	}
}

func createOrgInvitesTable(t *testing.T, db *DB) {
	t.Helper()
	if _, err := db.Exec(`
		CREATE TABLE organization_invites (
			id TEXT PRIMARY KEY,
			org_id TEXT NOT NULL,
			email TEXT NOT NULL,
			role TEXT NOT NULL,
			code_hash TEXT NOT NULL,
			invited_by TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL
		)`); err != nil {
		t.Fatal(err)
	}
}

func seedOrgInvite(t *testing.T, db *DB, id, codeHash string, expiresAt time.Time) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := db.Exec(`
		INSERT INTO organization_invites (id, org_id, email, role, code_hash, invited_by, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, id, "o1", "a@example.com", "member", codeHash, "admin-1", expiresAt, now); err != nil {
		t.Fatal(err)
	}
}

func orgInvitePresent(t *testing.T, db *DB, id string) bool {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM organization_invites WHERE id = ?", id,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestOrgInviteClaim_RequiresCodeHash(t *testing.T) {
	db := newSQLiteTestDB(t)
	createOrgInvitesTable(t, db)
	seedOrgInvite(t, db, "i1", "hash-A", time.Now().UTC().Add(time.Hour))
	repo := NewOrgInviteRepository(db)
	ctx := context.Background()

	// A rotated code (different hash, same invite ID) must not redeem: the
	// claim binds the invite row to the exact code that was validated.
	claimed, err := repo.ClaimInvite(ctx, "i1", "hash-rotated")
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("claim with a stale code hash consumed the invite")
	}
	if !orgInvitePresent(t, db, "i1") {
		t.Fatal("failed claim deleted the invite row")
	}

	claimed, err = repo.ClaimInvite(ctx, "i1", "hash-A")
	if err != nil {
		t.Fatal(err)
	}
	if !claimed {
		t.Fatal("claim with the current code hash did not consume the invite")
	}
	if orgInvitePresent(t, db, "i1") {
		t.Fatal("successful claim left the invite row behind")
	}

	claimed, err = repo.ClaimInvite(ctx, "i1", "hash-A")
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("second claim on a consumed invite reported success")
	}
}

func TestOrgInviteClaim_RejectsExpired(t *testing.T) {
	db := newSQLiteTestDB(t)
	createOrgInvitesTable(t, db)
	seedOrgInvite(t, db, "i1", "hash-A", time.Now().UTC().Add(-time.Minute))
	repo := NewOrgInviteRepository(db)

	claimed, err := repo.ClaimInvite(context.Background(), "i1", "hash-A")
	if err != nil {
		t.Fatal(err)
	}
	if claimed {
		t.Fatal("claim consumed an expired invite")
	}
	if !orgInvitePresent(t, db, "i1") {
		t.Fatal("failed claim deleted the invite row")
	}
}

func TestOrgDelete_ReportsMissingRow(t *testing.T) {
	db := newSQLiteTestDB(t)
	if _, err := db.Exec(`CREATE TABLE organizations (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	repo := NewOrgRepository(db)
	ctx := context.Background()

	deleted, err := repo.Delete(ctx, "missing")
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Fatal("delete of a missing org reported a deletion")
	}

	if _, err := db.Exec(`INSERT INTO organizations (id) VALUES (?)`, "o1"); err != nil {
		t.Fatal(err)
	}
	deleted, err = repo.Delete(ctx, "o1")
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("delete of an existing org reported no deletion")
	}
	deleted, err = repo.Delete(ctx, "o1")
	if err != nil {
		t.Fatal(err)
	}
	if deleted {
		t.Fatal("repeat delete reported a deletion — concurrent double-deletes must observe this")
	}
}

func TestAddMember_DuplicateKeySurfaces(t *testing.T) {
	db := newSQLiteTestDB(t)
	// Mirrors the real schema's PRIMARY KEY (org_id, user_id): the unique
	// constraint is the backstop a second concurrent add loses against.
	if _, err := db.Exec(`
		CREATE TABLE organization_members (
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL,
			joined_at DATETIME NOT NULL,
			PRIMARY KEY (org_id, user_id)
		)`); err != nil {
		t.Fatal(err)
	}
	repo := NewOrgRepository(db)
	ctx := context.Background()
	member := &domain.OrgMember{OrgID: "o1", UserID: "u1", Role: domain.OrgRoleMember, JoinedAt: time.Now().UTC()}

	if err := repo.AddMember(ctx, member); err != nil {
		t.Fatalf("first add failed: %v", err)
	}
	err := repo.AddMember(ctx, member)
	if !errors.Is(err, port.ErrDuplicateKey) {
		t.Fatalf("second add err = %v, want port.ErrDuplicateKey", err)
	}
}
