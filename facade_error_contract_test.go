package goauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
)

func TestDisabledOrganizationMiddlewareErrorEnvelope(t *testing.T) {
	a := &Auth{}
	for _, tc := range []struct {
		name string
		wrap func(http.Handler) http.Handler
	}{
		{"organization", a.RequireOrg(domain.OrgRoleMember)},
		{"active organization", a.RequireActiveOrg(domain.OrgRoleMember)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("disabled organization handler ran")
			})).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/private", nil))
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Content-Type") != "application/json" ||
				len(body) != 2 || body["error"] != "organizations_disabled" || body["message"] == "" {
				t.Fatalf("unexpected error response: status=%d header=%v body=%v", rec.Code, rec.Header(), body)
			}
		})
	}
}
