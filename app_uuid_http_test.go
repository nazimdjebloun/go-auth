package goauth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
)

func TestAppPermissionsUUIDInputsHTTP(t *testing.T) {
	f := newAppHTTPFixture(t, true, false)
	permissions := f.a.Services().AppPermissions
	permission, err := permissions.CreatePermission(t.Context(), api.CreateAppPermissionInput{
		Actor: f.admin, Key: "app.uuid.read", Name: "UUID test",
	})
	if err != nil {
		t.Fatal(err)
	}
	role, err := permissions.CreateRole(t.Context(), api.CreateAppRoleInput{
		Actor: f.admin, Slug: "uuid-test", Name: "UUID test",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Canonical IDs returned by the API still resolve through actual SQL reads
	// and writes, rather than merely satisfying the validator.
	f.request(t, "GET", "/admin/authorization/users/"+f.admin.UserID+"/role", "", f.token, 200)
	f.request(t, "GET", "/admin/authorization/users/"+f.admin.UserID+"/access", "", f.token, 200)
	f.request(t, "PATCH", "/admin/authorization/roles/"+role.ID, `{"expectedRevision":1,"name":"Updated"}`, f.token, 200)
	f.request(t, "PATCH", "/admin/authorization/permissions/"+permission.ID, `{"expectedRevision":1,"name":"Updated"}`, f.token, 200)

	const id = "abcdefab-1234-4234-8234-abcdefabcdef"
	for _, test := range []struct {
		name, id string
	}{
		{"uppercase", strings.ToUpper(id)},
		{"compact", strings.ReplaceAll(id, "-", "")},
		{"braces", "{" + id + "}"},
		{"urn", "urn:uuid:" + id},
		{"leading_space", " " + id},
		{"trailing_space", id + " "},
		{"malformed", "not-a-uuid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			pathID := url.PathEscape(test.id)
			for _, request := range []struct {
				name, method, path, body string
			}{
				{"user_role", "GET", "/admin/authorization/users/" + pathID + "/role", ""},
				{"user_access", "GET", "/admin/authorization/users/" + pathID + "/access", ""},
				{"role", "PATCH", "/admin/authorization/roles/" + pathID, `{"expectedRevision":1,"name":"Rejected"}`},
				{"permission", "PATCH", "/admin/authorization/permissions/" + pathID, `{"expectedRevision":1,"name":"Rejected"}`},
				{"assignment_role", "PUT", "/admin/authorization/users/" + f.admin.UserID + "/role", fmt.Sprintf(`{"roleId":%q,"expectedRoleRevision":1,"expectedAssignmentRevision":1}`, test.id)},
				{"role_filter", "GET", "/admin/users?appRoleId=" + url.QueryEscape(test.id), ""},
			} {
				t.Run(request.name, func(t *testing.T) {
					w := f.request(t, request.method, request.path, request.body, f.token, 400)
					var result struct {
						Error string `json:"error"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					if result.Error != "invalid_input" {
						t.Fatalf("error=%q, want invalid_input: %s", result.Error, w.Body.String())
					}
				})
			}
		})
	}
}
