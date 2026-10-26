package migrations

import (
	"testing"

	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

// Exercise the actual published additive upgrade with existing credentials,
// memberships, invitations and host-owned objects, rather than an empty schema.
func TestSelectedBackendOrgPermissionsPopulatedUpgrade(t *testing.T) {
	for _, mode := range []string{"executed", "adopted"} {
		t.Run(mode, func(t *testing.T) {
			db := testdb.OpenSelected(t)
			dialect := testdb.Driver(db)
			options := Options{Driver: dialect}
			baseline := bootstrapCatalog(t, dialect)
			applyBootstrap(t, db, dialect)
			hash, password := seedUpgradeData(t, db, dialect)
			const orgID = "99999999-9999-9999-9999-999999999991"
			const inviteID = "99999999-9999-9999-9999-999999999992"
			upgradeExec(t, db, dialect, `INSERT INTO organizations(id,name,slug,created_by,owner_count,member_count,created_at,updated_at) VALUES (?,'Preserved','preserved',?,1,2,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, orgID, upgradeUser)
			upgradeExec(t, db, dialect, `INSERT INTO organization_members(org_id,user_id,role,joined_at) VALUES (?,?,'owner',CURRENT_TIMESTAMP)`, orgID, upgradeUser)
			upgradeExec(t, db, dialect, `INSERT INTO organization_members(org_id,user_id,role,joined_at) VALUES (?,?,'admin',CURRENT_TIMESTAMP)`, orgID, upgradeOAuth)
			upgradeExec(t, db, dialect, `INSERT INTO organization_invites(id,org_id,email,role,code_hash,invited_by,expires_at,created_at) VALUES (?,?,'invited@example.com','member',?,?,'2030-01-01 00:00:00',CURRENT_TIMESTAMP)`, inviteID, orgID, fixtureChecksum("org-invite"), upgradeUser)
			if mode == "adopted" {
				upgradeExec(t, db, dialect, "DROP TABLE goauth_migrations")
				if _, err := runCatalog(t.Context(), db, options, baseline, "adopt", 1); err != nil {
					t.Fatal(err)
				}
			}
			catalog, err := Load(dialect)
			if err != nil {
				t.Fatal(err)
			}
			status, err := Apply(t.Context(), db, options)
			if err != nil {
				t.Fatal(err)
			}
			if status.Revision != catalog.TargetRevision || status.Dirty || len(status.Pending) != 0 {
				t.Fatalf("incomplete upgrade: %+v", status)
			}
			assertUpgradeData(t, db, dialect, hash, password)
			var valid bool
			query := `SELECT (SELECT COUNT(*) FROM organization_members WHERE org_id=? AND role='owner')=1 AND (SELECT COUNT(*) FROM organization_members WHERE org_id=? AND role='admin')=1 AND (SELECT COUNT(*) FROM organization_invites WHERE id=? AND code_hash=?)=1 AND (SELECT COUNT(*) FROM org_roles)=0 AND (SELECT COUNT(*) FROM org_authorization_state)=0`
			if err = db.QueryRowContext(t.Context(), bind(dialect, query), orgID, orgID, inviteID, fixtureChecksum("org-invite")).Scan(&valid); err != nil || !valid {
				t.Fatalf("legacy org state changed: %v", err)
			}
			if err = Verify(t.Context(), db, options); err != nil {
				t.Fatal(err)
			}
			if _, err = Apply(t.Context(), db, options); err != nil {
				t.Fatal("repeat upgrade:", err)
			}
		})
	}
}
