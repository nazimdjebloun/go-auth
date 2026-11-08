package goauth

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
)

func TestAuthorizationHTTPRevisionPreconditions(t *testing.T) {
	for _, namespace := range []string{"app", "org"} {
		t.Run(namespace, func(t *testing.T) {
			f := newAppHTTPFixture(t, true, false, WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true, EnableManagementHTTP: true}))
			base := "/admin/authorization"
			if namespace == "org" {
				org, err := f.a.Trusted().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Revisions", Slug: uuid.NewString()})
				if err != nil {
					t.Fatal(err)
				}
				base = "/auth/orgs/" + org.ID + "/authorization"
			}
			var permission, role struct {
				ID       string `json:"id"`
				Revision uint64 `json:"revision"`
				Name     string `json:"name"`
			}
			w := f.request(t, "POST", base+"/permissions", `{"key":"`+namespace+`.tasks.read","name":"Read tasks"}`, f.token, 201)
			if err := json.Unmarshal(w.Body.Bytes(), &permission); err != nil {
				t.Fatal(err)
			}
			w = f.request(t, "POST", base+"/roles", `{"slug":"revision-test","name":"Revision test","permissionKeys":[]}`, f.token, 201)
			if err := json.Unmarshal(w.Body.Bytes(), &role); err != nil {
				t.Fatal(err)
			}
			p, r := base+"/permissions/"+permission.ID, base+"/roles/"+role.ID
			for _, request := range []struct{ name, method, path, body string }{
				{"update permission", "PATCH", p, `{"name":"Changed"}`},
				{"delete permission", "DELETE", p, ""},
				{"update role", "PATCH", r, `{"name":"Changed"}`},
				{"replace grants", "PUT", r + "/permissions", `{"permissionKeys":[]}`},
				{"delete role", "DELETE", r, ""},
			} {
				t.Run(request.name+" requires header", func(t *testing.T) { f.request(t, request.method, request.path, request.body, f.token, 400) })
			}
			f.request(t, "DELETE", p+"?expectedRevision=1", "", f.token, 400)
			f.requestRevision(t, "DELETE", p+"?expectedRevision=1", "", f.token, 400, 1)
			f.requestRevision(t, "PATCH", p, `{"expectedRevision":1,"name":"Old transport"}`, f.token, 400, 1)
			w = f.requestRevision(t, "PATCH", p, `{"name":"Changed"}`, f.token, 200, 1)
			if err := json.Unmarshal(w.Body.Bytes(), &permission); err != nil || permission.Revision != 2 {
				t.Fatalf("permission=%+v error=%v", permission, err)
			}
			f.requestRevision(t, "PATCH", p, `{"name":"Stale"}`, f.token, http.StatusPreconditionFailed, 1)
			f.requestRevision(t, "DELETE", p, "", f.token, http.StatusPreconditionFailed, 1)
			f.requestRevision(t, "PATCH", r, `{"name":"Changed"}`, f.token, 200, 1)
			f.requestRevision(t, "PATCH", r, `{"name":"Stale"}`, f.token, http.StatusPreconditionFailed, 1)
			f.requestRevision(t, "DELETE", r, "", f.token, http.StatusPreconditionFailed, 1)
			f.requestRevision(t, "PUT", r+"/permissions", `{"permissionKeys":[]}`, f.token, 200, 2)
			// Even replacing grants with the same set consumes the checked revision.
			f.requestRevision(t, "PUT", r+"/permissions", `{"permissionKeys":[]}`, f.token, http.StatusPreconditionFailed, 2)
			f.requestRevision(t, "DELETE", p, "", f.token, 204, 2)
			f.requestRevision(t, "DELETE", r, "", f.token, 204, 3)
		})
	}
}
