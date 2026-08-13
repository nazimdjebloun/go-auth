package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	return body
}

func TestRequireOrgMember_MissingOrgID(t *testing.T) {
	orgs := testutil.NewMockOrgRepo()
	userKeyFn := func(context.Context) string { return "user-1" }

	handler := RequireOrgMember(orgs, userKeyFn)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	body := decodeErrorBody(t, rec)
	if body["error"] != "invalid_input" {
		t.Errorf("expected invalid_input, got %s", body["error"])
	}
	if body["message"] == "" {
		t.Error("expected a non-empty message")
	}
}

func TestRequireOrgMember_MissingUser(t *testing.T) {
	orgs := testutil.NewMockOrgRepo()
	userKeyFn := func(context.Context) string { return "" }

	handler := RequireOrgMember(orgs, userKeyFn)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetPathValue("orgID", "org-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	body := decodeErrorBody(t, rec)
	if body["error"] != "unauthorized" {
		t.Errorf("expected unauthorized, got %s", body["error"])
	}
}

func TestRequireOrgMember_NotAMember(t *testing.T) {
	orgs := testutil.NewMockOrgRepo()
	userKeyFn := func(context.Context) string { return "outsider" }

	handler := RequireOrgMember(orgs, userKeyFn)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetPathValue("orgID", "org-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Matches domain.ErrOrgMemberNotFound / OrgService.requireRole exactly —
	// a direct-service caller and an HTTP caller must see the same response
	// for the same logical failure (nonexistent org or non-member, both
	// collapse to this since orgs.GetMembership returns nil either way).
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	body := decodeErrorBody(t, rec)
	if body["error"] != "org_member_not_found" {
		t.Errorf("expected org_member_not_found, got %s", body["error"])
	}
	if body["message"] != domain.ErrOrgMemberNotFound.Message {
		t.Errorf("expected message %q, got %q", domain.ErrOrgMemberNotFound.Message, body["message"])
	}
}

func TestRequireOrgMember_Success(t *testing.T) {
	orgs := testutil.NewMockOrgRepo()
	orgs.AddMember(context.Background(), &domain.OrgMember{
		OrgID: "org-1", UserID: "user-1", Role: domain.OrgRoleMember,
	})
	userKeyFn := func(context.Context) string { return "user-1" }

	called := false
	handler := RequireOrgMember(orgs, userKeyFn)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if GetOrgID(r.Context()) != "org-1" {
			t.Errorf("expected org-1 in context, got %q", GetOrgID(r.Context()))
		}
		if GetOrgRole(r.Context()) != domain.OrgRoleMember {
			t.Errorf("expected member role in context, got %q", GetOrgRole(r.Context()))
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetPathValue("orgID", "org-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Fatal("expected inner handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRequireOrgMember_RepoError(t *testing.T) {
	orgs := testutil.NewMockOrgRepo()
	orgs.GetMembershipErr = errors.New("db down")
	userKeyFn := func(context.Context) string { return "user-1" }

	handler := RequireOrgMember(orgs, userKeyFn)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetPathValue("orgID", "org-1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// A repository failure must surface as a 500, not masquerade as a
	// not-a-member 404.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	body := decodeErrorBody(t, rec)
	if body["error"] != "internal_error" {
		t.Errorf("expected internal_error, got %s", body["error"])
	}
	if body["message"] == "" {
		t.Error("expected a non-empty message")
	}
}

func TestRequireOrgRole_InsufficientRole(t *testing.T) {
	handler := RequireOrgRole(domain.OrgRoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), orgRoleKey, domain.OrgRoleMember)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req.WithContext(ctx))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	body := decodeErrorBody(t, rec)
	if body["error"] != "org_forbidden" {
		t.Errorf("expected org_forbidden, got %s", body["error"])
	}
	if body["message"] != domain.ErrOrgForbidden.Message {
		t.Errorf("expected message %q, got %q", domain.ErrOrgForbidden.Message, body["message"])
	}
}

func TestRequireOrgRole_SufficientRole(t *testing.T) {
	called := false
	handler := RequireOrgRole(domain.OrgRoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(req.Context(), orgRoleKey, domain.OrgRoleOwner)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req.WithContext(ctx))

	if !called {
		t.Fatal("expected inner handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
