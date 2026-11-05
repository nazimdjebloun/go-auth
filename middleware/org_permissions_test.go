package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

type orgPermissionCheckFunc func(context.Context, api.CheckOrgPermissionInput) (*api.OrgPermissionDecision, error)

func (f orgPermissionCheckFunc) CheckPermission(ctx context.Context, in api.CheckOrgPermissionInput) (*api.OrgPermissionDecision, error) {
	return f(ctx, in)
}

func TestRequireOrgPermission_PopulatesResolvedMembershipScope(t *testing.T) {
	for _, tc := range []struct {
		name   string
		active bool
	}{
		{name: "path organization"}, {name: "active organization", active: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			checker := orgPermissionCheckFunc(func(_ context.Context, in api.CheckOrgPermissionInput) (*api.OrgPermissionDecision, error) {
				calls++
				if in.Actor.OrgID != "authorized" || in.Actor.UserID != "user" || in.Actor.SessionID != "session" || in.PermissionKey != "org.tasks.read" {
					t.Fatalf("actor=%+v", in)
				}
				return &api.OrgPermissionDecision{Allowed: true, MembershipRole: domain.OrgRoleMember}, nil
			})
			r := httptest.NewRequest("GET", "/", nil)
			r.SetPathValue("orgID", "authorized")
			activeID, staleRole := "authorized", "owner"
			ctx := ContextWithUser(r.Context(), &domain.User{ID: "user"})
			ctx = ContextWithSession(ctx, &domain.Session{ID: "session", UserID: "user", ActiveOrgID: &activeID, ActiveOrgRole: &staleRole})
			wrap := RequireOrgPermission(checker, "org.tasks.read")
			if tc.active {
				r.SetPathValue("orgID", "ignored")
				wrap = RequireActiveOrgPermission(checker, "org.tasks.read")
			}
			w := httptest.NewRecorder()
			wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if GetOrgID(r.Context()) != "authorized" || GetOrgRole(r.Context()) != domain.OrgRoleMember {
					t.Fatal("scope did not use the live permission decision")
				}
				w.WriteHeader(204)
			})).ServeHTTP(w, r.WithContext(ctx))
			if w.Code != 204 || calls != 1 {
				t.Fatalf("status=%d checks=%d", w.Code, calls)
			}
		})
	}
}

func TestRequireOrgPermission_FailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		decision *api.OrgPermissionDecision
		err      error
		status   int
	}{
		{name: "nil decision", status: 403},
		{name: "denied", decision: &api.OrgPermissionDecision{}, status: 403},
		{name: "missing membership role", decision: &api.OrgPermissionDecision{Allowed: true}, status: 500},
		{name: "backend failure", err: errors.New("database unavailable"), status: 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checker := orgPermissionCheckFunc(func(context.Context, api.CheckOrgPermissionInput) (*api.OrgPermissionDecision, error) {
				return tc.decision, tc.err
			})
			r := httptest.NewRequest("GET", "/", nil)
			r.SetPathValue("orgID", "org")
			r = r.WithContext(ContextWithUser(r.Context(), &domain.User{ID: "user"}))
			w := httptest.NewRecorder()
			RequireOrgPermission(checker, "org.tasks.read")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthorized handler ran") })).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}
