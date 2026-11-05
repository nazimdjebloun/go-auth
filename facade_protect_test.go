package goauth

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

func TestProtectMutationSecurityAndParameters(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithRateLimitRoute("POST /widgets/{id}", ratelimit.Rate{Requests: 3, Window: time.Minute}))
	called := 0
	h := f.a.Protect("POST /widgets/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if middleware.GetUserFromContext(r.Context()) == nil {
			t.Error("missing authenticated user")
		}
		if r.PathValue("id") == "" || r.Pattern != "POST /widgets/{id}" {
			t.Error("missing canonical routing context")
		}
		w.WriteHeader(204)
	}))
	f.mux.Handle("POST /widgets/{id}", h)
	// CORS preflight must not authenticate or spend the mutation's budget.
	r := httptest.NewRequest("OPTIONS", "/widgets/1", nil)
	r.Header.Set("Origin", "http://localhost")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != "http://localhost" || w.Header().Get("X-RateLimit-Limit") != "" {
		t.Fatalf("preflight: %d %v", w.Code, w.Header())
	}
	// Invalid origin and missing double-submit proof both stop before business code.
	r = httptest.NewRequest("POST", "/widgets/1", nil)
	r.Header.Set("Origin", "https://evil.example")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("origin: %d", w.Code)
	}
	r = httptest.NewRequest("POST", "/widgets/1", nil)
	r.Header.Set("Origin", "http://localhost")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF: %d", w.Code)
	}
	f.request(t, "POST", "/widgets/1", "", f.token, 204)
	f.request(t, "POST", "/widgets/2", "", f.token, 429)
	if called != 1 {
		t.Fatalf("business handler called %d times", called)
	}
}

func TestProtectLiveVerificationExpiryAndAuthorization(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithRegistration(RegistrationConfig{RequireEmailVerification: true}))
	h := f.a.Protect("GET /widgets/{id}", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, html.EscapeString(r.PathValue("id")))
	}))
	f.mux.Handle("GET /widgets/{id}", h)
	f.mux.Handle("GET /private-admin", f.a.Protect("GET /private-admin", f.a.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))))
	f.request(t, "GET", "/widgets/one", "", "", 401)
	id := uuid.NewString()
	now := time.Now().UTC()
	if err := f.users.Create(t.Context(), &domain.User{ID: id, Email: id + "@example.test", Role: domain.RoleUser, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	session, err := f.a.Services().Session.Create(t.Context(), api.CreateSessionInput{UserID: id})
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/widgets/one", "", session.SessionToken, 403)
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET is_verified=true WHERE id=$1", id); err != nil {
		t.Fatal(err)
	}
	if got := f.request(t, "GET", "/widgets/one", "", session.SessionToken, 200).Body.String(); got != "one" {
		t.Fatalf("path value: %q", got)
	}
	f.request(t, "GET", "/private-admin", "", session.SessionToken, 403)
	// A patternless transport still receives PathValue from the inner ServeMux.
	r := httptest.NewRequest("GET", "/widgets/direct", nil)
	r.Header.Set("Cookie", f.a.cookies.Name+"="+session.SessionToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "direct" {
		t.Fatalf("direct transport: %d %s", w.Code, w.Body.String())
	}
	if _, err := f.db.ExecContext(t.Context(), "UPDATE sessions SET expires_at=$1,refresh_expires_at=$2 WHERE id=$3", now.Add(-time.Hour), now.Add(-time.Hour), session.Session.ID); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/widgets/one", "", session.SessionToken, 401)
}

func TestProtectRejectsInvalidSetup(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	for _, pattern := range []string{"", "POST /widgets/*", "POST /widgets/{id"} {
		t.Run(pattern, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid pattern accepted")
				}
			}()
			f.a.Protect(pattern, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		})
	}
	defer func() {
		if recover() == nil {
			t.Fatal("nil handler accepted")
		}
	}()
	f.a.Protect("GET /nil", nil)
}

func TestProtectRejectsMismatchedRoute(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	h := f.a.Protect("GET /widgets/{id}", http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { t.Fatal("mismatch reached business code") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/other/one", strings.NewReader("")))
	if w.Code != 404 {
		t.Fatalf("mismatch: %d", w.Code)
	}
}

func TestProtectOrganizationScopes(t *testing.T) {
	f := newOrgPermissionsRegressionFixture(t)
	const key = "org.tasks.write"
	svc := f.a.Services().OrgPermissions
	permission, err := svc.CreatePermission(t.Context(), api.CreateOrgPermissionInput{Actor: f.actor, Key: key, Name: "Write tasks"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetRolePermissions(t.Context(), api.SetOrgRolePermissionsInput{Actor: f.actor, RoleID: f.role.ID, ExpectedRevision: 1, PermissionKeys: []string{key}}); err != nil {
		t.Fatal(err)
	}
	memberActor := api.OrgPermissionActor{UserID: f.memberID, OrgID: f.actor.OrgID}
	// Resolve the member's current session without putting identity into the handler.
	_, sessionUser, err := f.a.Services().Session.ValidateWithUser(t.Context(), f.memberToken)
	if err != nil || sessionUser.ID != f.memberID {
		t.Fatalf("member identity: %v", err)
	}
	session, err := f.a.Services().Session.Validate(t.Context(), f.memberToken)
	if err != nil {
		t.Fatal(err)
	}
	memberActor.SessionID = session.ID
	if err := f.a.Services().Org.SetActiveOrg(t.Context(), api.SetActiveOrgInput{SessionID: session.ID, UserID: f.memberID, OrgID: f.actor.OrgID}); err != nil {
		t.Fatal(err)
	}
	// A second RequireOrg would perform a redundant membership query.
	f.a.orgMemberMW = func(http.Handler) http.Handler { t.Fatal("duplicate membership middleware"); return nil }
	called := 0
	next := func(w http.ResponseWriter, r *http.Request, scope OrgScope) {
		called++
		if scope.OrgID != memberActor.OrgID || scope.UserID != memberActor.UserID || scope.Role != domain.OrgRoleMember {
			t.Fatalf("scope=%+v", scope)
		}
		if r.Pattern == "" {
			t.Fatal("missing route pattern")
		}
		w.WriteHeader(204)
	}
	pathPattern := "POST /scoped/{orgID}/tasks"
	activePattern := "POST /active-scoped/{orgID}/tasks"
	path := "/scoped/" + f.actor.OrgID + "/tasks"
	activePath := "/active-scoped/" + uuid.NewString() + "/tasks"
	f.mux.Handle(pathPattern, f.a.ProtectOrgScope(pathPattern, key, next))
	f.mux.Handle(activePattern, f.a.ProtectActiveOrgScope(activePattern, key, next))
	// Existing scope helpers also compose safely through Protect.
	composedPattern := "POST /composed/{orgID}/tasks"
	f.mux.Handle(composedPattern, f.a.Protect(composedPattern, f.a.RequireOrgPermissionScope(key, next)))
	f.request(t, "POST", path, "", f.memberToken, 204)
	f.request(t, "POST", activePath, "", f.memberToken, 204)
	f.request(t, "POST", "/composed/"+f.actor.OrgID+"/tasks", "", f.memberToken, 204)
	f.request(t, "POST", path, "", "", 401)
	r := httptest.NewRequest("POST", path, nil)
	r.Header.Set("Origin", "http://localhost")
	r.AddCookie(&http.Cookie{Name: f.a.cookies.Name, Value: f.memberToken})
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("missing CSRF status=%d", w.Code)
	}
	disabled := false
	if _, err := svc.UpdatePermission(t.Context(), api.UpdateOrgPermissionInput{Actor: f.actor, PermissionID: permission.ID, ExpectedRevision: 1, IsEnabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	f.request(t, "POST", path, "", f.memberToken, 403)
	f.request(t, "POST", activePath, "", f.memberToken, 403)
	if called != 3 {
		t.Fatalf("business calls=%d", called)
	}
}

func TestProtectOrganizationScopesRejectInvalidSetup(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	for _, tc := range []struct {
		name  string
		build func() http.Handler
	}{
		{name: "path nil handler", build: func() http.Handler { return f.a.ProtectOrgScope("GET /orgs/{orgID}", "org.tasks.read", nil) }},
		{name: "active nil handler", build: func() http.Handler { return f.a.ProtectActiveOrgScope("GET /tasks", "org.tasks.read", nil) }},
		{name: "invalid pattern", build: func() http.Handler {
			return f.a.ProtectOrgScope("GET /{", "org.tasks.read", func(http.ResponseWriter, *http.Request, OrgScope) {})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid setup did not panic")
				}
			}()
			tc.build()
		})
	}
}
