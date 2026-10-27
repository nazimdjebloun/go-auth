package goauth

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
)

type orgPermissionsRegressionFixture struct {
	appHTTPFixture
	actor       api.OrgPermissionActor
	memberID    string
	memberToken string
	role        *domain.OrgPermissionRole
}

func newOrgPermissionsRegressionFixture(t *testing.T) orgPermissionsRegressionFixture {
	t.Helper()
	f := newAppHTTPFixture(t, true, false,
		WithMailer(noopMailer{}),
		WithAudit(AuditConfig{Enabled: true}),
		WithOrganizations(OrganizationConfig{Enable: true}),
		WithOrgPermissions(OrgPermissionsConfig{Enable: true, EnableManagementHTTP: true}),
	)
	org, err := f.a.Services().Org.CreateOrg(t.Context(), api.CreateOrgInput{
		OwnerID: f.admin.UserID, Name: "Regression", Slug: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	actor := api.OrgPermissionActor{OrgID: org.ID, UserID: f.admin.UserID, SessionID: f.admin.SessionID}
	member, err := f.a.Register(t.Context(), api.RegisterInput{
		Email: uuid.NewString() + "@example.com", Password: "Test-Password-123!", Name: "Member",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.a.Services().Org.AddMember(t.Context(), api.AddMemberInput{
		OrgID: org.ID, ActorID: actor.UserID, ActorSessionID: actor.SessionID,
		UserID: member.User.ID, Role: domain.OrgRoleMember,
	}); err != nil {
		t.Fatal(err)
	}
	role, err := f.a.Services().OrgPermissions.CreateRole(t.Context(), api.CreateOrgRoleInput{
		Actor: actor, Slug: "restricted", Name: "Restricted",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Services().OrgPermissions.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{
		Actor: actor, UserID: member.User.ID, RoleID: role.ID, ExpectedRoleRevision: role.Revision,
	}); err != nil {
		t.Fatal(err)
	}
	return orgPermissionsRegressionFixture{
		appHTTPFixture: f, actor: actor, memberID: member.User.ID,
		memberToken: member.SessionToken, role: role,
	}
}

func TestOrgPermissionsHTTPInspectIneligibleTargetRole(t *testing.T) {
	f := newOrgPermissionsRegressionFixture(t)
	base := "/auth/orgs/" + f.actor.OrgID
	path := base + "/authorization/members/" + f.memberID + "/role"
	// Permission to inspect comes from the caller, including for self-inspection.
	f.request(t, "GET", path, "", f.memberToken, 403)
	disabled := false
	if _, err := f.a.Services().OrgPermissions.UpdateRole(t.Context(), api.UpdateOrgRoleInput{
		Actor: f.actor, RoleID: f.role.ID, ExpectedRevision: f.role.Revision, IsEnabled: &disabled,
	}); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []bool{false, true} {
		if _, err := f.db.ExecContext(t.Context(), `UPDATE users SET is_banned=$1 WHERE id=$2`, banned, f.memberID); err != nil {
			t.Fatal(err)
		}
		w := f.request(t, "GET", path, "", f.token, 200)
		var result api.OrgMemberRoleResult
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Role.ID != f.role.ID || result.Role.IsEnabled || result.AssignmentRevision != 1 {
			t.Fatalf("banned=%v: unexpected target assignment: %+v", banned, result)
		}
		w = f.request(t, "GET", base+"/authorization/members/"+f.memberID+"/access", "", f.token, 200)
		var access api.OrgAccess
		if err := json.Unmarshal(w.Body.Bytes(), &access); err != nil {
			t.Fatal(err)
		}
		if access.Role.ID != f.role.ID || access.Role.IsEnabled || access.IsFullAccess || len(access.PermissionKeys) != 0 || access.AssignmentRevision != 1 {
			t.Fatalf("banned=%v: unexpected target access: %+v", banned, access)
		}
	}
	f.request(t, "GET", base+"/authorization/members/"+uuid.NewString()+"/role", "", f.token, 404)
	other, err := f.a.Services().Org.CreateOrg(t.Context(), api.CreateOrgInput{
		OwnerID: f.actor.UserID, Name: "Other", Slug: uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/auth/orgs/"+other.ID+"/authorization/members/"+f.memberID+"/role", "", f.token, 404)
	// The observed assignment revision is usable for recovery without re-enabling the old role.
	roles, err := f.a.Services().OrgPermissions.ListRoles(t.Context(), api.ListOrgRolesInput{Actor: f.actor})
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range roles {
		if role.Slug == "member" {
			body := fmt.Sprintf(`{"roleId":%q,"expectedRoleRevision":%d,"expectedAssignmentRevision":1}`, role.ID, role.Revision)
			f.request(t, "PUT", path, body, f.token, 200)
			return
		}
	}
	t.Fatal("protected member role missing")
}

func TestOrgPermissionsHTTPInviteRoleIDValidation(t *testing.T) {
	f := newOrgPermissionsRegressionFixture(t)
	path := "/auth/orgs/" + f.actor.OrgID + "/invites"
	invalid := []string{
		"not-a-uuid", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", strings.ReplaceAll(f.role.ID, "-", ""),
		"urn:uuid:" + f.role.ID, "{" + f.role.ID + "}",
	}
	for _, id := range invalid {
		body := fmt.Sprintf(`{"email":"invalid@example.com","orgRoleId":%q,"expectedRoleRevision":1}`, id)
		w := f.request(t, "POST", path, body, f.token, 400)
		if !strings.Contains(w.Body.String(), `"error":"invalid_input"`) {
			t.Fatalf("role ID %q: %s", id, w.Body.String())
		}
	}
	var count int
	if err := f.db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM organization_invites WHERE org_id=$1`, f.actor.OrgID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("invalid input committed %d invitations", count)
	}
	body := fmt.Sprintf(`{"email":"missing@example.com","orgRoleId":%q,"expectedRoleRevision":1}`, uuid.NewString())
	f.request(t, "POST", path, body, f.token, 404)
	body = fmt.Sprintf(`{"email":"valid@example.com","orgRoleId":%q,"expectedRoleRevision":1}`, f.role.ID)
	f.request(t, "POST", path, body, f.token, 201)
}

func TestOrgPermissionsDisabledFixedRoleWritesPreserveOwnership(t *testing.T) {
	f := newOrgPermissionsRegressionFixture(t)
	cfg := f.a.cfg
	WithOrgPermissions(OrgPermissionsConfig{})(&cfg)
	legacy, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(legacy.Close)
	if legacy.Services().OrgPermissions != nil {
		t.Fatal("disabled capability is exposed")
	}
	// A same-classification write explicitly resets the retained custom role.
	if err := legacy.Services().Org.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{
		OrgID: f.actor.OrgID, ActorID: f.actor.UserID, UserID: f.memberID, NewRole: domain.OrgRoleMember,
	}); err != nil {
		t.Fatal(err)
	}
	assignment, err := f.a.Services().OrgPermissions.GetMemberRole(t.Context(), api.GetOrgMemberRoleInput{
		Actor: f.actor, UserID: f.memberID,
	})
	if err != nil || assignment.Role.Slug != "member" || assignment.AssignmentRevision != 2 {
		t.Fatalf("disabled fixed-role reset: %+v, error=%v", assignment, err)
	}
	for _, input := range []api.UpdateMemberRoleInput{
		{OrgID: f.actor.OrgID, ActorID: f.actor.UserID, UserID: f.memberID, NewRole: domain.OrgRoleOwner},
		{OrgID: f.actor.OrgID, ActorID: f.actor.UserID, UserID: f.actor.UserID, NewRole: domain.OrgRoleMember},
	} {
		if err := legacy.Services().Org.UpdateMemberRole(t.Context(), input); err != nil {
			t.Fatal(err)
		}
	}
	WithOrgPermissions(OrgPermissionsConfig{Enable: true})(&cfg)
	restored, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restored.Close)
	owner := api.OrgPermissionActor{OrgID: f.actor.OrgID, UserID: f.memberID}
	if _, err := restored.Services().OrgPermissions.UpdateLibraryPermissions(t.Context(), api.UpdateOrgLibraryPermissionsInput{
		Actor: owner, Create: []string{"goauth.org.members.read"},
	}); err != nil {
		t.Fatal("restored sole owner cannot manage permissions:", err)
	}
	org, err := restored.Services().Org.GetByID(t.Context(), api.GetOrgInput{OrgID: owner.OrgID, ActorID: owner.UserID})
	if err != nil || org.OwnerCount != 1 {
		t.Fatalf("owner invariants: %+v, error=%v", org, err)
	}
}

func TestOrgPermissionsPersistedAuditAttribution(t *testing.T) {
	f := newOrgPermissionsRegressionFixture(t)
	if _, err := f.a.Services().OrgPermissions.CreatePermission(t.Context(), api.CreateOrgPermissionInput{
		Actor: f.actor, Key: "org.audit.read", Name: "Read",
	}); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []audit.EventType{
		audit.EventOrgAuthorizationInitialized, audit.EventOrgPermissionCreated,
		audit.EventOrgRoleCreated, audit.EventOrgMemberRoleChanged,
	} {
		var success bool
		var actorID, orgID *string
		err := f.db.QueryRowContext(t.Context(),
			`SELECT success,actor_id,org_id FROM audit_log WHERE event_type=$1`, string(typ),
		).Scan(&success, &actorID, &orgID)
		if err != nil {
			t.Fatal(err)
		}
		if !success || actorID == nil || *actorID != f.actor.UserID || orgID == nil || *orgID != f.actor.OrgID {
			t.Fatalf("%s: success=%v actorID=%v orgID=%v", typ, success, actorID, orgID)
		}
	}
}
