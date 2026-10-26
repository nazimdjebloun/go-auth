package goauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func TestOrgPermissionsHTTPManagementAndLiveAccess(t *testing.T) {
	f := newAppHTTPFixture(t, true, false, WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true, EnableManagementHTTP: true}))
	org, err := f.a.Services().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Example", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	actor := api.OrgPermissionActor{OrgID: org.ID, UserID: f.admin.UserID, SessionID: f.admin.SessionID}
	base := "/auth/orgs/" + org.ID
	reg, err := f.a.Register(t.Context(), api.RegisterInput{Email: uuid.NewString() + "@example.com", Password: "Test-Password-123!", Name: "Member"})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.a.Services().Org.AddMember(t.Context(), api.AddMemberInput{OrgID: org.ID, ActorID: f.admin.UserID, ActorSessionID: f.admin.SessionID, UserID: reg.User.ID, Role: domain.OrgRoleMember}); err != nil {
		t.Fatal(err)
	}
	f.request(t, "PATCH", base+"/authorization/library-permissions", `{"create":["goauth.org.organization.update"]}`, f.token, 200)
	w := f.request(t, "POST", base+"/authorization/permissions", `{"key":"org.projects.read","name":"Read projects"}`, f.token, 201)
	var permission domain.OrgPermission
	if err = json.Unmarshal(w.Body.Bytes(), &permission); err != nil {
		t.Fatal(err)
	}
	w = f.request(t, "POST", base+"/authorization/roles", `{"slug":"editor","name":"Editor","permissionKeys":["org.projects.read","goauth.org.organization.update"]}`, f.token, 201)
	var role domain.OrgPermissionRole
	if err = json.Unmarshal(w.Body.Bytes(), &role); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"roleId":%q,"expectedRoleRevision":1,"expectedAssignmentRevision":0}`, role.ID)
	f.request(t, "PUT", base+"/authorization/members/"+reg.User.ID+"/role", body, f.token, 200)
	f.request(t, "PUT", base+"/authorization/members/"+reg.User.ID+"/role", body, f.token, 409)
	f.request(t, "PUT", base, `{"name":"Delegated update"}`, reg.SessionToken, 200)
	f.request(t, "GET", base+"/members", "", reg.SessionToken, 403)
	f.request(t, "POST", base+"/authorization/roles", `{"slug":"forged","name":"Forged","actor":{"userId":"owner"}}`, f.token, 400)
	w = f.request(t, "GET", base+"/access", "", reg.SessionToken, 200)
	var access api.OrgAccess
	if err = json.Unmarshal(w.Body.Bytes(), &access); err != nil || access.Role.ID != role.ID || access.IsFullAccess {
		t.Fatalf("access=%+v %v", access, err)
	}
	if strings.Contains(w.Body.String(), "assignment_revision") {
		t.Fatal("snake_case leaked into public JSON")
	}
	f.mux.Handle("GET /projects/{orgID}", f.a.RequireOrgPermissionScope("org.projects.read", func(w http.ResponseWriter, r *http.Request, scope OrgScope) {
		if scope.OrgID != org.ID {
			t.Error("wrong tenant scope")
		}
		w.WriteHeader(204)
	}))
	f.request(t, "GET", "/projects/"+org.ID, "", reg.SessionToken, 204)
	other, err := f.a.Services().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Other", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/projects/"+other.ID, "", reg.SessionToken, 404)
	if err = f.a.Services().Org.SetActiveOrg(t.Context(), api.SetActiveOrgInput{SessionID: reg.Session.ID, UserID: reg.User.ID, OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	f.mux.Handle("GET /active-projects", f.a.RequireActiveOrgPermissionScope("org.projects.read", func(w http.ResponseWriter, r *http.Request, scope OrgScope) {
		if scope.OrgID != org.ID {
			t.Error("wrong active tenant")
		}
		w.WriteHeader(204)
	}))
	f.request(t, "GET", "/active-projects", "", reg.SessionToken, 204)
	disabled := false
	if _, err = f.a.Services().OrgPermissions.UpdatePermission(t.Context(), api.UpdateOrgPermissionInput{Actor: actor, PermissionID: permission.ID, ExpectedRevision: 1, IsEnabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/projects/"+org.ID, "", reg.SessionToken, 403)
	f.request(t, "GET", "/active-projects", "", reg.SessionToken, 403)
	// Revoked sessions are checked again even for direct permission-service calls.
	if err = f.a.Services().Session.RevokeByID(t.Context(), reg.Session.ID); err != nil {
		t.Fatal(err)
	}
	_, err = f.a.Services().OrgPermissions.CheckPermission(t.Context(), api.CheckOrgPermissionInput{Actor: api.OrgPermissionActor{OrgID: org.ID, UserID: reg.User.ID, SessionID: reg.Session.ID}, PermissionKey: "goauth.org.organization.update"})
	if !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("revoked actor session: %v", err)
	}
}

func TestOrgPermissionsOptionalManagementAndDisabledMiddleware(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true}))
	org, err := f.a.Services().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Org", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/auth/orgs/"+org.ID+"/access", "", f.token, 200)
	f.request(t, "GET", "/auth/orgs/"+org.ID+"/authorization/roles", "", f.token, 404)
	var disabled *Auth = &Auth{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(middleware.ContextWithUser(r.Context(), &domain.User{ID: uuid.NewString()}))
	disabled.RequireOrgPermission("org.projects.read")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("disabled middleware allowed access") })).ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("disabled permission middleware status=%d", w.Code)
	}
	if disabled.Services().OrgPermissions != nil {
		t.Fatal("disabled capability exposed a typed nil")
	}
	if _, err = NewConfig(minimalOpts(WithOrgPermissions(OrgPermissionsConfig{Enable: true}))...); err == nil {
		t.Fatal("org permissions accepted without organizations")
	}
}

func TestOrgPermissionsWithoutAppPermissions(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true}))
	cfg := f.a.cfg
	WithAppPermissions(AppPermissionsConfig{})(&cfg)
	a, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if a.Services().AppPermissions != nil || a.Services().OrgPermissions == nil {
		t.Fatal("org capability depends on app permissions")
	}
	org, err := a.Services().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Independent", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Services().OrgPermissions.CreatePermission(t.Context(), api.CreateOrgPermissionInput{Actor: api.OrgPermissionActor{OrgID: org.ID, UserID: f.admin.UserID, SessionID: f.admin.SessionID}, Key: "org.independent.read", Name: "Independent"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestOrgPermissionsDisabledAfterUseStillAllowsOrganizationDeletion(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true}))
	org, err := f.a.Services().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Disable later", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	actor := api.OrgPermissionActor{OrgID: org.ID, UserID: f.admin.UserID, SessionID: f.admin.SessionID}
	role, err := f.a.Services().OrgPermissions.CreateRole(t.Context(), api.CreateOrgRoleInput{Actor: actor, Slug: "empty-role", Name: "Empty"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := f.a.Register(t.Context(), api.RegisterInput{Email: uuid.NewString() + "@example.com", Password: "Test-Password-123!", Name: "Member"})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.a.Services().Org.AddMember(t.Context(), api.AddMemberInput{OrgID: org.ID, ActorID: f.admin.UserID, ActorSessionID: f.admin.SessionID, UserID: user.User.ID, Role: domain.OrgRoleMember}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.a.Services().OrgPermissions.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: actor, UserID: user.User.ID, RoleID: role.ID, ExpectedRoleRevision: 1}); err != nil {
		t.Fatal(err)
	}
	cfg := f.a.cfg
	WithOrgPermissions(OrgPermissionsConfig{})(&cfg)
	a, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err = a.Services().Org.DeleteOrg(t.Context(), api.DeleteOrgInput{OrgID: org.ID, ActorID: f.admin.UserID, ActorSessionID: f.admin.SessionID}); err != nil {
		t.Fatal("persisted granular links blocked legacy deletion:", err)
	}
}
