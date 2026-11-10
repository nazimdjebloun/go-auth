package goauth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
)

func TestOrgPermissionsUUIDInputsHTTP(t *testing.T) {
	f := newAppHTTPFixture(t, true, false, WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true, EnableManagementHTTP: true}))
	org, err := f.a.Trusted().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Example", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}

	// Canonical IDs returned by the API still resolve through actual SQL reads,
	// rather than merely satisfying the validator.
	base := "/auth/orgs/" + org.ID
	f.request(t, "GET", base+"/authorization/members/"+f.admin.UserID+"/role", "", f.token, 200)
	f.request(t, "GET", base+"/authorization/members/"+f.admin.UserID+"/access", "", f.token, 200)

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
				{"member_role", "GET", base + "/authorization/members/" + pathID + "/role", ""},
				{"member_access", "GET", base + "/authorization/members/" + pathID + "/access", ""},
				{"assignment", "PUT", base + "/authorization/members/" + f.admin.UserID + "/role", fmt.Sprintf(`{"roleId":%q}`, test.id)},
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
