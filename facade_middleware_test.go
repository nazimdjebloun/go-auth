package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
)

type tenantRecordStore map[string]map[string]string

// get requires the complete authorized scope rather than accepting a loose
// org ID. The test store mirrors the repository boundary recommended to
// consumers for tenant-owned application data.
func (s tenantRecordStore) get(_ context.Context, scope OrgScope, recordID string) (string, bool) {
	records, ok := s[scope.OrgID]
	if !ok {
		return "", false
	}
	value, ok := records[recordID]
	return value, ok
}

func registerForScopedRoute(t *testing.T, a *Auth, email string) *RegisterResult {
	t.Helper()
	result, err := a.Register(context.Background(), RegisterInput{
		Email:    email,
		Password: validTestPassword(),
		Name:     "Scoped route user",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if result.Session == nil || result.SessionToken == "" {
		t.Fatal("Register did not return an authenticated session")
	}
	return result
}

func addSessionCookies(t *testing.T, a *Auth, req *http.Request, result *RegisterResult) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.SetSessionCookies(rec, result.SessionToken, result.RefreshToken)
	for _, cookie := range rec.Result().Cookies() {
		req.AddCookie(cookie)
	}
}

func TestRequireOrgScope_BindsAuthorizedTenantToHandler(t *testing.T) {
	a := buildAuth(t, minimalOpts(WithOrganizations(OrganizationConfig{Enable: true}))...)
	defer a.Close()

	account := registerForScopedRoute(t, a, "scope-owner@example.com")
	orgA, err := a.Services().Org.CreateOrg(context.Background(), CreateOrgInput{
		Name: "Tenant A", Slug: "tenant-a", OwnerID: account.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrg tenant A: %v", err)
	}
	orgB, err := a.Services().Org.CreateOrg(context.Background(), CreateOrgInput{
		Name: "Tenant B", Slug: "tenant-b", OwnerID: account.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrg tenant B: %v", err)
	}

	records := tenantRecordStore{
		orgA.ID: {"shared-id": "tenant-a-record"},
		orgB.ID: {"shared-id": "tenant-b-record"},
	}
	var receivedScope OrgScope
	handler := a.RequireOrgScope(domain.OrgRoleMember, func(w http.ResponseWriter, r *http.Request, scope OrgScope) {
		receivedScope = scope
		value, ok := records.get(r.Context(), scope, r.PathValue("recordID"))
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
	})

	for _, test := range []struct {
		name string
		org  *domain.Organization
		want string
	}{
		{name: "tenant A", org: orgA, want: "tenant-a-record"},
		{name: "tenant B", org: orgB, want: "tenant-b-record"},
	} {
		t.Run(test.name, func(t *testing.T) {
			receivedScope = OrgScope{}
			req := httptest.NewRequest(http.MethodGet, "/orgs/placeholder/records/shared-id", nil)
			req.SetPathValue("orgID", test.org.ID)
			req.SetPathValue("recordID", "shared-id")
			addSessionCookies(t, a, req, account)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			var body map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body["value"] != test.want {
				t.Errorf("value = %q, want %q", body["value"], test.want)
			}
			if receivedScope.OrgID != test.org.ID {
				t.Errorf("scope.OrgID = %q, want %q", receivedScope.OrgID, test.org.ID)
			}
			if receivedScope.UserID != account.User.ID {
				t.Errorf("scope.UserID = %q, want %q", receivedScope.UserID, account.User.ID)
			}
			if receivedScope.Role != domain.OrgRoleOwner {
				t.Errorf("scope.Role = %q, want %q", receivedScope.Role, domain.OrgRoleOwner)
			}
		})
	}
}

func TestRequireOrgScope_RejectsBeforeCallingHandler(t *testing.T) {
	a := buildAuth(t, minimalOpts(WithOrganizations(OrganizationConfig{Enable: true}))...)
	defer a.Close()

	owner := registerForScopedRoute(t, a, "scope-owner-2@example.com")
	org, err := a.Services().Org.CreateOrg(context.Background(), CreateOrgInput{
		Name: "Private tenant", Slug: "private-tenant", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}
	outsider := registerForScopedRoute(t, a, "scope-outsider@example.com")

	called := false
	handler := a.RequireOrgScope(domain.OrgRoleMember, func(http.ResponseWriter, *http.Request, OrgScope) {
		called = true
	})

	tests := []struct {
		name       string
		account    *RegisterResult
		wantStatus int
	}{
		{name: "unauthenticated", wantStatus: http.StatusUnauthorized},
		{name: "not a member", account: outsider, wantStatus: http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called = false
			req := httptest.NewRequest(http.MethodGet, "/orgs/placeholder/records", nil)
			req.SetPathValue("orgID", org.ID)
			if test.account != nil {
				addSessionCookies(t, a, req, test.account)
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, test.wantStatus, rec.Body.String())
			}
			if called {
				t.Fatal("scoped handler ran before authentication and membership checks succeeded")
			}
		})
	}
}

func TestRequireActiveOrgScope_UsesSessionTenant(t *testing.T) {
	a := buildAuth(t, minimalOpts(WithOrganizations(OrganizationConfig{Enable: true}))...)
	defer a.Close()

	account := registerForScopedRoute(t, a, "active-scope-owner@example.com")
	org, err := a.Services().Org.CreateOrg(context.Background(), CreateOrgInput{
		Name: "Active tenant", Slug: "active-tenant", OwnerID: account.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrg: %v", err)
	}

	called := false
	var receivedScope OrgScope
	handler := a.RequireActiveOrgScope(domain.OrgRoleAdmin, func(w http.ResponseWriter, _ *http.Request, scope OrgScope) {
		called = true
		receivedScope = scope
		w.WriteHeader(http.StatusNoContent)
	})

	before := httptest.NewRequest(http.MethodGet, "/projects", nil)
	addSessionCookies(t, a, before, account)
	beforeRec := httptest.NewRecorder()
	handler.ServeHTTP(beforeRec, before)
	if beforeRec.Code != http.StatusBadRequest {
		t.Fatalf("before SetActiveOrg status = %d, want %d", beforeRec.Code, http.StatusBadRequest)
	}
	if called {
		t.Fatal("scoped handler ran without an active organization")
	}

	if err := a.Services().Org.SetActiveOrg(context.Background(), SetActiveOrgInput{
		SessionID: account.Session.ID,
		UserID:    account.User.ID,
		OrgID:     org.ID,
	}); err != nil {
		t.Fatalf("SetActiveOrg: %v", err)
	}

	after := httptest.NewRequest(http.MethodGet, "/projects", nil)
	addSessionCookies(t, a, after, account)
	afterRec := httptest.NewRecorder()
	handler.ServeHTTP(afterRec, after)
	if afterRec.Code != http.StatusNoContent {
		t.Fatalf("after SetActiveOrg status = %d, want %d; body = %s", afterRec.Code, http.StatusNoContent, afterRec.Body.String())
	}
	if !called {
		t.Fatal("scoped handler was not called after active-org authorization")
	}
	if receivedScope.OrgID != org.ID || receivedScope.UserID != account.User.ID || receivedScope.Role != domain.OrgRoleOwner {
		t.Errorf("received scope = %+v, want org=%q user=%q role=%q", receivedScope, org.ID, account.User.ID, domain.OrgRoleOwner)
	}
}

func TestOrgScopeHandler_FailsClosedOnIncompleteMiddlewareContext(t *testing.T) {
	a := &Auth{}
	called := false
	handler := a.orgScopeHandler(func(http.ResponseWriter, *http.Request, OrgScope) {
		called = true
	})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/projects", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	if called {
		t.Fatal("scoped handler ran with an incomplete middleware context")
	}
	if contentType := rec.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != domain.ErrInternal.Code {
		t.Errorf("error = %q, want %q", body["error"], domain.ErrInternal.Code)
	}
}
