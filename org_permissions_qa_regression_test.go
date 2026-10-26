package goauth

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

func TestOrgPermissionsHTTPBusinessDeletionDelegation(t *testing.T) {
	f := newOrgPermissionsRegressionFixture(t)
	svc := f.a.Services().OrgPermissions
	keys := []string{"goauth.org.permissions.update", "goauth.org.permissions.delete"}
	if _, err := svc.UpdateLibraryPermissions(t.Context(), api.UpdateOrgLibraryPermissionsInput{
		Actor: f.actor, Create: keys,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetRolePermissions(t.Context(), api.SetOrgRolePermissionsInput{
		Actor: f.actor, RoleID: f.role.ID, ExpectedRevision: 1, PermissionKeys: keys,
	}); err != nil {
		t.Fatal(err)
	}
	p, err := svc.CreatePermission(t.Context(), api.CreateOrgPermissionInput{
		Actor: f.actor, Key: "org.payroll.export", Name: "Export payroll",
	})
	if err != nil {
		t.Fatal(err)
	}
	var revisionBefore uint64
	if err := f.db.QueryRowContext(t.Context(),
		`SELECT revision FROM org_authorization_state WHERE org_id=$1`, f.actor.OrgID,
	).Scan(&revisionBefore); err != nil {
		t.Fatal(err)
	}
	path := "/auth/orgs/" + f.actor.OrgID + "/authorization/permissions/" + p.ID
	f.request(t, "PATCH", path, `{"expectedRevision":1,"name":"Changed"}`, f.memberToken, 403)
	f.request(t, "DELETE", path+"?expectedRevision=1", "", f.memberToken, 403)
	var revisionAfter uint64
	if err := f.db.QueryRowContext(t.Context(),
		`SELECT revision FROM org_authorization_state WHERE org_id=$1`, f.actor.OrgID,
	).Scan(&revisionAfter); err != nil || revisionAfter != revisionBefore {
		t.Fatalf("denied deletion changed authorization revision: %d -> %d, error=%v", revisionBefore, revisionAfter, err)
	}
	var deletedEvents int
	if err := f.db.QueryRowContext(t.Context(),
		`SELECT COUNT(*) FROM audit_log WHERE org_id=$1 AND event_type='org.permission.deleted'`, f.actor.OrgID,
	).Scan(&deletedEvents); err != nil || deletedEvents != 0 {
		t.Fatalf("denied deletion recorded a deletion: count=%d error=%v", deletedEvents, err)
	}
	decision, err := svc.CheckPermission(t.Context(), api.CheckOrgPermissionInput{Actor: f.actor, PermissionKey: p.Key})
	if err != nil || !decision.Allowed {
		t.Fatalf("denied deletion removed owner's access: %+v error=%v", decision, err)
	}
	// Holding the key satisfies delegation, but the grant still protects the definition.
	if _, err := svc.SetRolePermissions(t.Context(), api.SetOrgRolePermissionsInput{
		Actor: f.actor, RoleID: f.role.ID, ExpectedRevision: 2, PermissionKeys: append(keys, p.Key),
	}); err != nil {
		t.Fatal(err)
	}
	w := f.request(t, "DELETE", path+"?expectedRevision=1", "", f.memberToken, 409)
	if !strings.Contains(w.Body.String(), `"error":"org_permission_in_use"`) {
		t.Fatalf("referenced permission deletion: %s", w.Body.String())
	}
	if _, err := svc.SetRolePermissions(t.Context(), api.SetOrgRolePermissionsInput{
		Actor: f.actor, RoleID: f.role.ID, ExpectedRevision: 3, PermissionKeys: keys,
	}); err != nil {
		t.Fatal(err)
	}
	f.request(t, "DELETE", path+"?expectedRevision=1", "", f.token, 204)
	decision, err = svc.CheckPermission(t.Context(), api.CheckOrgPermissionInput{Actor: f.actor, PermissionKey: p.Key})
	if err != nil || decision.Allowed {
		t.Fatalf("owner's deletion did not remove definition: %+v error=%v", decision, err)
	}
}

func TestOrgPermissionsHTTPInspectDisabledEffectiveAccess(t *testing.T) {
	f := newOrgPermissionsRegressionFixture(t)
	svc := f.a.Services().OrgPermissions
	const key = "org.tasks.read"
	if _, err := svc.CreatePermission(t.Context(), api.CreateOrgPermissionInput{
		Actor: f.actor, Key: key, Name: "Read tasks",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetRolePermissions(t.Context(), api.SetOrgRolePermissionsInput{
		Actor: f.actor, RoleID: f.role.ID, ExpectedRevision: 1, PermissionKeys: []string{key},
	}); err != nil {
		t.Fatal(err)
	}
	base := "/auth/orgs/" + f.actor.OrgID
	path := base + "/authorization/members/" + f.memberID
	read := func() api.OrgAccess {
		t.Helper()
		w := f.request(t, "GET", path+"/access", "", f.token, 200)
		var access api.OrgAccess
		if err := json.Unmarshal(w.Body.Bytes(), &access); err != nil {
			t.Fatal(err)
		}
		return access
	}
	if access := read(); !slices.Contains(access.PermissionKeys, key) {
		t.Fatalf("enabled role lost access: %+v", access)
	}
	f.request(t, "GET", path+"/access", "", f.memberToken, 403)
	disabled := false
	if _, err := svc.UpdateRole(t.Context(), api.UpdateOrgRoleInput{
		Actor: f.actor, RoleID: f.role.ID, ExpectedRevision: 2, IsEnabled: &disabled,
	}); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", base+"/access", "", f.memberToken, 403)
	access := read()
	if access.PermissionKeys == nil || len(access.PermissionKeys) != 0 || access.IsFullAccess {
		t.Fatalf("disabled target retains effective access: %+v", access)
	}
	if access.Role.ID != f.role.ID || access.Role.IsEnabled || access.AssignmentRevision != 1 {
		t.Fatalf("disabled target lost assignment metadata: %+v", access)
	}
	if !slices.Contains(access.Role.PermissionKeys, key) {
		t.Fatalf("disabled role lost configured grants: %+v", access.Role)
	}
	if _, err := f.db.ExecContext(t.Context(), `UPDATE users SET is_banned=true WHERE id=$1`, f.memberID); err != nil {
		t.Fatal(err)
	}
	enabled := true
	if _, err := svc.UpdateRole(t.Context(), api.UpdateOrgRoleInput{
		Actor: f.actor, RoleID: f.role.ID, ExpectedRevision: 3, IsEnabled: &enabled,
	}); err != nil {
		t.Fatal(err)
	}
	if access := read(); len(access.PermissionKeys) != 0 || access.IsFullAccess || !access.Role.IsEnabled {
		t.Fatalf("banned target incorrectly gains effective access: %+v", access)
	}
	// Even a banned owner must not be presented as currently having full access.
	roles, err := svc.ListRoles(t.Context(), api.ListOrgRolesInput{Actor: f.actor})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if role.Slug == "owner" {
			if _, err := svc.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{
				Actor: f.actor, UserID: f.memberID, RoleID: role.ID,
				ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: 1,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	access = read()
	if !access.Role.IsOwner() || access.IsFullAccess || len(access.PermissionKeys) != 0 {
		t.Fatalf("banned owner effective access: %+v", access)
	}
	f.request(t, "GET", base+"/authorization/members/"+uuid.NewString()+"/access", "", f.token, 404)
	other, err := f.a.Services().Org.CreateOrg(t.Context(), api.CreateOrgInput{
		OwnerID: f.actor.UserID, Name: "Other", Slug: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/auth/orgs/"+other.ID+"/authorization/members/"+f.memberID+"/access", "", f.token, 404)
}

func TestOrgPermissionsHTTPStaleInvitationRecovery(t *testing.T) {
	for _, change := range []string{"metadata", "disable"} {
		t.Run(change, func(t *testing.T) {
			f := newOrgPermissionsRegressionFixture(t)
			account, err := f.a.Register(t.Context(), api.RegisterInput{
				Email: uuid.NewString() + "@example.com", Password: "Test-Password-123!", Name: "Invitee",
			})
			if err != nil {
				t.Fatal(err)
			}
			create := func(revision uint64) *domain.OrgInvite {
				t.Helper()
				invite, err := f.a.Services().OrgInvite.CreateOrgInvite(t.Context(), api.CreateOrgInviteInput{
					OrgID: f.actor.OrgID, InvitedBy: f.actor.UserID, ActorSessionID: f.actor.SessionID,
					Email: account.User.Email, OrgRoleID: f.role.ID, ExpectedRoleRevision: revision,
				})
				if err != nil {
					t.Fatal(err)
				}
				return invite
			}
			invite := create(1)
			input := api.UpdateOrgRoleInput{Actor: f.actor, RoleID: f.role.ID, ExpectedRevision: 1}
			if change == "metadata" {
				name := "Renamed"
				input.Name = &name
			} else {
				disabled := false
				input.IsEnabled = &disabled
			}
			updated, err := f.a.Services().OrgPermissions.UpdateRole(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			read := func() (domain.OrgInvite, uint64, uint64) {
				t.Helper()
				var stored domain.OrgInvite
				var savedRole, state uint64
				err := f.db.QueryRowContext(t.Context(), `SELECT i.code_hash,i.expires_at,r.role_revision,s.revision
					FROM organization_invites i
					JOIN org_invite_roles r ON r.org_id=i.org_id AND r.invite_id=i.id
					JOIN org_authorization_state s ON s.org_id=i.org_id
					WHERE i.org_id=$1 AND i.id=$2`, f.actor.OrgID, invite.ID,
				).Scan(&stored.CodeHash, &stored.ExpiresAt, &savedRole, &state)
				if err != nil {
					t.Fatal(err)
				}
				return stored, savedRole, state
			}
			before, savedBefore, stateBefore := read()
			var auditBefore int
			if err := f.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_log WHERE org_id=$1`, f.actor.OrgID).Scan(&auditBefore); err != nil {
				t.Fatal(err)
			}
			base := "/auth/orgs/" + f.actor.OrgID
			path := base + "/invites/" + invite.ID
			body := fmt.Sprintf(`{"code":%q}`, invite.RawCode)
			for _, request := range []struct{ path, body, token string }{
				{"/auth/orgs/invites/accept", body, account.SessionToken},
				{"/auth/orgs/invites/accept", body, account.SessionToken},
				{path + "/resend", "", f.token},
			} {
				w := f.request(t, "POST", request.path, request.body, request.token, 409)
				var response map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response["error"] != "org_invite_role_changed" || !strings.Contains(response["message"], "delete and recreate") {
					t.Fatalf("stale invitation lacks actionable error: %s", w.Body.String())
				}
			}
			after, savedAfter, stateAfter := read()
			if before.CodeHash != after.CodeHash || !before.ExpiresAt.Equal(after.ExpiresAt) {
				t.Fatal("stale invitation acceptance/resend changed the token or expiry")
			}
			if savedBefore != 1 || savedAfter != savedBefore || stateAfter != stateBefore {
				t.Fatalf("stale request changed frozen/state revisions: %d/%d %d/%d", savedBefore, savedAfter, stateBefore, stateAfter)
			}
			var auditAfter int
			if err := f.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM audit_log WHERE org_id=$1`, f.actor.OrgID).Scan(&auditAfter); err != nil || auditAfter != auditBefore {
				t.Fatalf("stale invitation attempt recorded a mutation: %d -> %d error=%v", auditBefore, auditAfter, err)
			}
			var memberships int
			if err := f.db.QueryRowContext(t.Context(),
				`SELECT COUNT(*) FROM organization_members WHERE org_id=$1 AND user_id=$2`, f.actor.OrgID, account.User.ID,
			).Scan(&memberships); err != nil || memberships != 0 {
				t.Fatalf("stale acceptance created membership: %d error=%v", memberships, err)
			}
			w := f.request(t, "PATCH", base+"/authorization/roles/"+f.role.ID,
				`{"expectedRevision":1,"name":"Stale write"}`, f.token, 409,
			)
			if !strings.Contains(w.Body.String(), `"error":"org_authorization_conflict"`) {
				t.Fatal("ordinary optimistic conflict changed its error code:", w.Body.String())
			}
			if !updated.IsEnabled {
				enabled := true
				updated, err = f.a.Services().OrgPermissions.UpdateRole(t.Context(), api.UpdateOrgRoleInput{
					Actor: f.actor, RoleID: updated.ID, ExpectedRevision: updated.Revision, IsEnabled: &enabled,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			f.request(t, "DELETE", path, "", f.token, 200)
			replacement := create(updated.Revision)
			f.request(t, "POST", "/auth/orgs/invites/accept",
				fmt.Sprintf(`{"code":%q}`, replacement.RawCode), account.SessionToken, 200,
			)
		})
	}
}
