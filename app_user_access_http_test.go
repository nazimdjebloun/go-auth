package goauth

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/routes"
)

func TestAppPermissionsTargetAccessHTTP(t *testing.T) {
	f := newAppHTTPFixture(t, true, true)
	ctx := t.Context()
	permissions := f.a.Services().AppPermissions
	register := func(email string) *api.RegisterResult {
		t.Helper()
		result, err := f.a.Register(ctx, api.RegisterInput{Email: email, Name: "Access test", Password: "Passw0rd!"})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	target := register("access-target@example.com")
	viewer := register("access-viewer@example.com")
	path := "/admin/authorization/users/" + target.User.ID + "/access"
	if _, ok := f.a.Handler(routes.GetAppUserAccess); !ok {
		t.Fatal("target access route missing")
	}
	f.request(t, "GET", path, "", "", 401)
	f.request(t, "GET", path, "", viewer.SessionToken, 403)
	f.request(t, "GET", "/admin/authorization/users/"+viewer.User.ID+"/access", "", viewer.SessionToken, 403)
	f.request(t, "GET", path, "", f.token, 403)
	if result, err := permissions.ListEffectivePermissions(ctx, api.ListAppEffectivePermissionsInput{
		Actor: api.AppPermissionActor{UserID: viewer.User.ID, SessionID: viewer.Session.ID}, UserID: target.User.ID,
	}); !errors.Is(err, domain.ErrTwoFactorRequired) || result != nil {
		t.Fatalf("unprivileged direct inspection accepted: %+v, %v", result, err)
	}

	verifySession := func(id string) {
		t.Helper()
		if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", time.Now().UTC(), id); err != nil {
			t.Fatal(err)
		}
	}
	verifySession(f.admin.SessionID)
	decode := func(w *httptest.ResponseRecorder) api.AppAccess {
		t.Helper()
		var result api.AppAccess
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	// Protected admin can inspect access even before roles.read is installed.
	baseline := decode(f.request(t, "GET", path, "", f.token, 200))
	if baseline.Role.ID != *target.User.AppRoleID || baseline.IsFullAccess || len(baseline.PermissionKeys) != 0 {
		t.Fatalf("baseline target access: %+v", baseline)
	}
	if baseline.AssignmentRevision != target.User.AppRoleAssignmentRevision || baseline.Revision == 0 {
		t.Fatalf("missing access revisions: %+v", baseline)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(f.request(t, "GET", path, "", f.token, 200).Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"role", "isFullAccess", "permissionKeys", "assignmentRevision", "revision"} {
		if _, ok := fields[key]; !ok {
			t.Fatalf("access JSON missing %s", key)
		}
	}
	f.request(t, "GET", "/admin/authorization/users/not-a-uuid/access", "", f.token, 400)
	f.request(t, "GET", "/admin/authorization/users/"+uuid.NewString()+"/access", "", f.token, 403)
	if result, err := permissions.ListEffectivePermissions(ctx, api.ListAppEffectivePermissionsInput{Actor: f.admin, UserID: "not-a-uuid"}); err == nil || result != nil {
		t.Fatalf("direct invalid target accepted: %+v, %v", result, err)
	}

	business, err := permissions.CreatePermission(ctx, api.CreateAppPermissionInput{Actor: f.admin, Key: "app.posts.read", Name: "Read posts"})
	if err != nil {
		t.Fatal(err)
	}
	targetRole, err := permissions.CreateRole(ctx, api.CreateAppRoleInput{Actor: f.admin, Slug: "access-target", Name: "Access target", PermissionKeys: []string{business.Key}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := permissions.SetUserRole(ctx, api.SetAppUserRoleInput{
		Actor: f.admin, UserID: target.User.ID, RoleID: targetRole.ID,
		ExpectedRoleRevision: targetRole.Revision, ExpectedAssignmentRevision: target.User.AppRoleAssignmentRevision,
	}); err != nil {
		t.Fatal(err)
	}
	verifySession(target.Session.ID)
	f.request(t, "GET", path, "", target.SessionToken, 403)
	if result, err := permissions.ListEffectivePermissions(ctx, api.ListAppEffectivePermissionsInput{
		Actor: api.AppPermissionActor{UserID: target.User.ID, SessionID: target.Session.ID}, UserID: f.admin.UserID,
	}); !errors.Is(err, domain.ErrForbidden) || result != nil {
		t.Fatalf("business grant authorized inspection: %+v, %v", result, err)
	}
	if _, err := permissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Create: []string{"goauth.app.roles.read"}}); err != nil {
		t.Fatal(err)
	}
	viewerRole, err := permissions.CreateRole(ctx, api.CreateAppRoleInput{Actor: f.admin, Slug: "access-viewer", Name: "Access viewer", PermissionKeys: []string{"goauth.app.roles.read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := permissions.SetUserRole(ctx, api.SetAppUserRoleInput{
		Actor: f.admin, UserID: viewer.User.ID, RoleID: viewerRole.ID,
		ExpectedRoleRevision: viewerRole.Revision, ExpectedAssignmentRevision: viewer.User.AppRoleAssignmentRevision,
	}); err != nil {
		t.Fatal(err)
	}
	viewerActor := api.AppPermissionActor{UserID: viewer.User.ID, SessionID: viewer.Session.ID}
	if result, err := permissions.ListEffectivePermissions(ctx, api.ListAppEffectivePermissionsInput{Actor: viewerActor, UserID: target.User.ID}); !errors.Is(err, domain.ErrTwoFactorRequired) || result != nil {
		t.Fatalf("direct inspection without MFA: %+v, %v", result, err)
	}
	f.request(t, "GET", path, "", viewer.SessionToken, 403)
	verifySession(viewer.Session.ID)
	access := decode(f.request(t, "GET", path+"?userID="+viewer.User.ID, "", viewer.SessionToken, 200))
	if access.Role.ID != targetRole.ID || access.IsFullAccess || !slices.Equal(access.PermissionKeys, []string{business.Key}) {
		t.Fatalf("inspection returned wrong account or grants: %+v", access)
	}
	if access.AssignmentRevision != target.User.AppRoleAssignmentRevision+1 || access.Revision <= baseline.Revision {
		t.Fatalf("inspection has stale revisions: %+v", access)
	}
	self := decode(f.request(t, "GET", "/auth/access", "", target.SessionToken, 200))
	if !reflect.DeepEqual(access, self) {
		t.Fatalf("target and self access differ: target=%+v self=%+v", access, self)
	}
	// Inspection checks the viewer's assurance, not the target's session.
	adminAccess := decode(f.request(t, "GET", "/admin/authorization/users/"+f.admin.UserID+"/access", "", viewer.SessionToken, 200))
	if !adminAccess.IsFullAccess || !slices.Contains(adminAccess.PermissionKeys, "goauth.app.roles.create") || !slices.Contains(adminAccess.PermissionKeys, business.Key) {
		t.Fatalf("protected admin policy missing: %+v", adminAccess)
	}
	if result, err := permissions.ListEffectivePermissions(ctx, api.ListAppEffectivePermissionsInput{
		Actor: api.AppPermissionActor{UserID: viewer.User.ID, SessionID: target.Session.ID}, UserID: target.User.ID,
	}); !errors.Is(err, domain.ErrForbidden) || result != nil {
		t.Fatalf("foreign actor session accepted: %+v, %v", result, err)
	}

	disabled := false
	if _, err := permissions.UpdatePermission(ctx, api.UpdateAppPermissionInput{Actor: f.admin, PermissionID: business.ID, ExpectedRevision: business.Revision, IsEnabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	after := decode(f.request(t, "GET", path, "", viewer.SessionToken, 200))
	if len(after.PermissionKeys) != 0 || after.Revision <= access.Revision {
		t.Fatalf("disabled permission still effective: %+v", after)
	}
	if _, err := permissions.UpdateRole(ctx, api.UpdateAppRoleInput{Actor: f.admin, RoleID: targetRole.ID, ExpectedRevision: targetRole.Revision, IsEnabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", path, "", viewer.SessionToken, 403)
	if _, err := permissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Delete: []string{"goauth.app.roles.read"}}); err != nil {
		t.Fatal(err)
	}
	adminPath := "/admin/authorization/users/" + f.admin.UserID + "/access"
	f.request(t, "GET", adminPath, "", viewer.SessionToken, 403)
	if result, err := permissions.ListEffectivePermissions(ctx, api.ListAppEffectivePermissionsInput{Actor: viewerActor, UserID: f.admin.UserID}); !errors.Is(err, domain.ErrForbidden) || result != nil {
		t.Fatalf("removed inspection permission accepted: %+v, %v", result, err)
	}
	f.request(t, "GET", adminPath, "", f.token, 200)
	if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET is_revoked=true WHERE id=$1", viewer.Session.ID); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", adminPath, "", viewer.SessionToken, 401)
	if result, err := permissions.ListEffectivePermissions(ctx, api.ListAppEffectivePermissionsInput{Actor: viewerActor, UserID: f.admin.UserID}); !errors.Is(err, domain.ErrSessionExpired) || result != nil {
		t.Fatalf("revoked viewer session accepted: %+v, %v", result, err)
	}
}
