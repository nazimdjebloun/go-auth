package goauth

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/routes"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

type appHTTPFixture struct {
	a     *Auth
	db    *sqlstore.DB
	users *sqlstore.UserRepository
	admin api.AppPermissionActor
	token string
	mux   *http.ServeMux
}

func newAppHTTPFixture(t *testing.T, management, requireMFA bool, options ...Option) appHTTPFixture {
	t.Helper()
	raw := testdb.OpenSelected(t)
	testdb.Apply(t, raw)
	db := sqlstore.NewDB(raw, testdb.Driver(raw))
	users := sqlstore.NewUserRepository(db).WithAppPermissions()
	now := time.Now().UTC()
	id := uuid.NewString()
	if err := users.Create(t.Context(), &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleAdmin, IsVerified: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	driver := DriverSQLite
	switch testdb.Driver(raw) {
	case "mysql":
		driver = DriverMySQL
	case "postgres", "pgx":
		driver = DriverPostgres
	}
	baseOptions := []Option{
		WithApp(AppConfig{Name: "Permissions", BaseURL: "http://localhost", Environment: EnvironmentDev, Database: DatabaseConfig{DB: raw, Driver: driver}}),
		WithSecret("0123456789abcdef0123456789abcdef"),
		WithBcryptCost(4),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		WithRegistration(RegistrationConfig{EnableEmailPassword: true, AllowPublic: true, EnableInvite: true}),
		WithSecurity(SecurityConfig{AllowedOrigins: []string{"http://localhost"}, DisableCSRFToken: true, AllowHTTPURLs: AllowPlaintextEmailLinks()}),
		WithTwoFactor(TwoFactorConfig{DisableAdminTwoFactor: !requireMFA}),
		WithAppPermissions(AppPermissionsConfig{Enable: true, EnableManagementHTTP: management}),
	}
	cfg, err := NewConfig(append(baseOptions, options...)...)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if err := a.InitializeAppPermissions(t.Context(), api.InitializeAppPermissionsInput{AdministratorUserID: id}); err != nil {
		t.Fatal(err)
	}
	session, err := a.Services().Session.Create(t.Context(), api.CreateSessionInput{UserID: id})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.Mount(mux)
	return appHTTPFixture{a: a, db: db, users: users, admin: api.AppPermissionActor{UserID: id, SessionID: session.Session.ID}, token: session.SessionToken, mux: mux}
}

func (f appHTTPFixture) request(t *testing.T, method, path, body, token string, want int) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Origin", "http://localhost")
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Cookie", f.a.cfg.cookie.Name+"="+token)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s status=%d want=%d: %s", method, path, w.Code, want, w.Body.String())
	}
	return w
}

func TestAppPermissionsHTTPUserRoleJSON(t *testing.T) {
	f := newAppHTTPFixture(t, true, false, WithOrganizations(OrganizationConfig{Enable: true}))
	decode := func(w *httptest.ResponseRecorder) map[string]json.RawMessage {
		t.Helper()
		var result map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	checkUser := func(user map[string]json.RawMessage) {
		t.Helper()
		if _, exists := user["role"]; exists {
			t.Fatalf("enabled user includes legacy role: %s", user["role"])
		}
		if _, exists := user["appRoleId"]; !exists {
			t.Fatal("enabled user lost appRoleId")
		}
	}
	w := f.request(t, "POST", "/auth/register", `{"email":"json-user@example.com","name":"JSON user","password":"Passw0rd!"}`, "", 201)
	var registered map[string]json.RawMessage
	if err := json.Unmarshal(decode(w)["user"], &registered); err != nil {
		t.Fatal(err)
	}
	checkUser(registered)
	me := decode(f.request(t, "GET", "/auth/me", "", f.token, 200))
	checkUser(me)
	if _, ok := me["hasPassword"]; !ok {
		t.Fatal("me response lost hasPassword")
	}
	if _, ok := me["session"]; !ok {
		t.Fatal("me response lost session")
	}
	created := decode(f.request(t, "POST", "/admin/users", `{"email":"json-created@example.com","name":"Created","password":"Passw0rd!"}`, f.token, 201))
	checkUser(created)
	var createdID string
	if err := json.Unmarshal(created["id"], &createdID); err != nil {
		t.Fatal(err)
	}
	detail := decode(f.request(t, "GET", "/admin/users/"+createdID, "", f.token, 200))
	var detailedUser map[string]json.RawMessage
	if err := json.Unmarshal(detail["user"], &detailedUser); err != nil {
		t.Fatal(err)
	}
	checkUser(detailedUser)
	listed := decode(f.request(t, "GET", "/admin/users", "", f.token, 200))
	var users []map[string]json.RawMessage
	if err := json.Unmarshal(listed["users"], &users); err != nil || len(users) != 3 {
		t.Fatalf("user list: %s, %v", listed["users"], err)
	}
	for _, user := range users {
		checkUser(user)
	}
	org := decode(f.request(t, "POST", "/auth/orgs", `{"name":"JSON team","slug":"json-team"}`, f.token, 201))
	var orgID string
	if err := json.Unmarshal(org["id"], &orgID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/auth/orgs/" + orgID + "/members", "/admin/orgs/" + orgID + "/members"} {
		body := decode(f.request(t, "GET", path, "", f.token, 200))
		var members []struct {
			Role string                     `json:"role"`
			User map[string]json.RawMessage `json:"user"`
		}
		if err := json.Unmarshal(body["members"], &members); err != nil || len(members) != 1 {
			t.Fatalf("member list: %s, %v", body["members"], err)
		}
		if members[0].Role != "owner" {
			t.Fatal("organization role changed")
		}
		checkUser(members[0].User)
	}
}

func TestAppPermissionsHTTPDelegationAndRevocation(t *testing.T) {
	f := newAppHTTPFixture(t, true, false)
	result, err := f.a.Register(t.Context(), api.RegisterInput{Email: "operator@example.com", Name: "Operator", Password: "Passw0rd!"})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.AppRoleID == nil || result.User.AppRoleAssignmentRevision != 1 {
		t.Fatal("signup did not assign baseline")
	}
	f.request(t, "GET", "/auth/me", "", result.SessionToken, 200)
	f.request(t, "GET", "/auth/access", "", result.SessionToken, 200)
	f.request(t, "GET", "/admin/users", "", result.SessionToken, 403)
	keys := `["goauth.app.users.read","goauth.app.sessions.revoke"]`
	f.request(t, "PATCH", "/admin/authorization/library-permissions", `{"create":`+keys+`}`, f.token, 200)
	w := f.request(t, "POST", "/admin/authorization/roles", `{"slug":"support","name":"Support","permissionKeys":`+keys+`}`, f.token, 201)
	var role domain.AppRole
	if err := json.Unmarshal(w.Body.Bytes(), &role); err != nil {
		t.Fatal(err)
	}
	body := `{"roleId":"` + role.ID + `","expectedRoleRevision":1,"expectedAssignmentRevision":1}`
	f.request(t, "PUT", "/admin/authorization/users/"+result.User.ID+"/role", body, f.token, 200)
	f.request(t, "GET", "/admin/users", "", result.SessionToken, 200)
	f.request(t, "GET", "/admin/users/count", "", result.SessionToken, 200)
	f.request(t, "GET", "/admin/stats", "", result.SessionToken, 403)
	f.request(t, "GET", "/admin/authorization/library-permissions", "", result.SessionToken, 403)
	f.request(t, "PATCH", "/admin/authorization/library-permissions", `{"create":["goauth.app.roles.create"]}`, result.SessionToken, 403)
	if _, err := f.a.Services().Admin.ListUsers(t.Context(), api.AdminListUsersInput{ActorID: result.User.ID, ActorSessionID: result.Session.ID}); err != nil {
		t.Fatal("direct call denied", err)
	}
	f.request(t, "PATCH", "/admin/authorization/library-permissions", `{"delete":["goauth.app.users.read"]}`, f.token, 200)
	f.request(t, "GET", "/admin/users", "", result.SessionToken, 403)
	f.request(t, "GET", "/admin/users", "", f.token, 200)
	f.request(t, "PATCH", "/admin/authorization/library-permissions", `{"create":["goauth.app.users.read"]}`, f.token, 200)
	f.request(t, "GET", "/admin/users", "", result.SessionToken, 403)
	// Actor context cannot be supplied through browser JSON.
	f.request(t, "PATCH", "/admin/authorization/library-permissions", `{"create":["goauth.app.stats.read"],"actor":{"userId":"x"}}`, f.token, 400)
	f.request(t, "PATCH", "/admin/authorization/library-permissions", `{"create":["goauth.app.stats.read"]} {}`, f.token, 400)
	// Last-admin checks use app identity even if the legacy column is stale.
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET role='user' WHERE id=$1", f.admin.UserID); err != nil {
		t.Fatal(err)
	}
	if err := f.a.Services().Admin.BanUser(t.Context(), api.BanUserInput{ActorID: f.admin.UserID, ActorSessionID: f.admin.SessionID, UserID: f.admin.UserID}); err == nil {
		t.Fatal("last protected admin ban allowed")
	}
}

func TestAppPermissionsHTTPCatalogWithoutDefinitionTable(t *testing.T) {
	f := newAppHTTPFixture(t, true, false)
	if _, err := f.db.ExecContext(t.Context(), "DROP TABLE app_role_permissions"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(t.Context(), "DROP TABLE app_permissions"); err != nil {
		t.Fatal(err)
	}
	w := f.request(t, "GET", "/admin/authorization/library-permissions", "", f.token, 200)
	if strings.Contains(w.Body.String(), "isInstalled") {
		t.Fatal("catalog includes database state")
	}
}

func TestAppPermissionsHTTPAccountCreationAndSessionDelegation(t *testing.T) {
	f := newAppHTTPFixture(t, true, false)
	operator, err := f.a.Register(t.Context(), api.RegisterInput{Email: "creator@example.com", Name: "Creator", Password: "Passw0rd!"})
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "PATCH", "/admin/authorization/library-permissions", `{"create":["goauth.app.users.create","goauth.app.sessions.revoke"]}`, f.token, 200)
	w := f.request(t, "POST", "/admin/authorization/roles", `{"slug":"creator","name":"Creator","permissionKeys":["goauth.app.users.create","goauth.app.sessions.revoke"]}`, f.token, 201)
	var role domain.AppRole
	if err := json.Unmarshal(w.Body.Bytes(), &role); err != nil {
		t.Fatal(err)
	}
	f.request(t, "PUT", "/admin/authorization/users/"+operator.User.ID+"/role", `{"roleId":"`+role.ID+`","expectedRoleRevision":1,"expectedAssignmentRevision":1}`, f.token, 200)
	f.request(t, "POST", "/admin/users", `{"email":"created@example.com","name":"Created","password":"Passw0rd!"}`, operator.SessionToken, 201)
	created, err := f.users.GetByEmail(t.Context(), "created@example.com")
	if err != nil || created == nil || created.AppRoleID == nil || *created.AppRoleID != *operator.User.AppRoleID {
		t.Fatalf("created account missing baseline: %+v %v", created, err)
	}
	admin, err := f.users.GetByID(t.Context(), f.admin.UserID)
	if err != nil {
		t.Fatal(err)
	}
	f.request(t, "POST", "/admin/users", `{"email":"escalated@example.com","name":"Escalated","password":"Passw0rd!","appRoleId":"`+*admin.AppRoleID+`","expectedRoleRevision":1}`, operator.SessionToken, 403)
	if u, err := f.users.GetByEmail(t.Context(), "escalated@example.com"); err != nil || u != nil {
		t.Fatalf("failed creation left an account: %+v %v", u, err)
	}
	session, err := f.a.Services().Session.Create(t.Context(), api.CreateSessionInput{UserID: created.ID})
	if err != nil {
		t.Fatal(err)
	}
	path := "/admin/users/" + created.ID + "/sessions"
	f.request(t, "GET", path, "", operator.SessionToken, 403)
	f.request(t, "DELETE", path+"/"+session.Session.ID, "", operator.SessionToken, 200)
	f.request(t, "GET", "/auth/me", "", session.SessionToken, 401)
	f.request(t, "GET", "/admin/users", "", operator.SessionToken, 403)
	f.request(t, "GET", "/admin/users?appRoleId=invalid", "", f.token, 400)
}

func TestAppPermissionsHTTPAssuranceAndOptionalManagement(t *testing.T) {
	f := newAppHTTPFixture(t, false, true)
	if _, ok := f.a.Handler(routes.AppAccess); !ok {
		t.Fatal("missing self access")
	}
	if _, ok := f.a.Handler(routes.AppLibraryPermissions); ok {
		t.Fatal("management exposed without opt-in")
	}
	if _, ok := f.a.Handler(routes.GetAppUserAccess); ok {
		t.Fatal("target access exposed without management opt-in")
	}
	f.request(t, "GET", "/admin/users", "", f.token, 403)
	if _, err := f.a.Services().Admin.ListUsers(t.Context(), api.AdminListUsersInput{ActorID: f.admin.UserID}); !errors.Is(err, domain.ErrTwoFactorRequired) {
		t.Fatalf("direct MFA bypass: %v", err)
	}
	now := time.Now().UTC()
	if _, err := f.db.ExecContext(t.Context(), "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", now, f.admin.SessionID); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/admin/users", "", f.token, 200)
	f.request(t, "GET", "/auth/access", "", f.token, 200)
}

func TestAppPermissionsStatsAuthorization(t *testing.T) {
	f := newAppHTTPFixture(t, true, true)
	ctx := t.Context()
	stats := func(actor api.AppPermissionActor) (*api.AdminStats, error) {
		return f.a.Services().Admin.GetStats(ctx, api.GetAdminStatsInput{
			ActorID: actor.UserID, ActorSessionID: actor.SessionID,
		})
	}
	for _, actor := range []api.AppPermissionActor{{UserID: f.admin.UserID}, f.admin} {
		if result, err := stats(actor); !errors.Is(err, domain.ErrTwoFactorRequired) || result != nil {
			t.Fatalf("stats without assurance: %+v, %v", result, err)
		}
	}
	f.request(t, "GET", "/admin/stats", "", f.token, 403)
	now := time.Now().UTC()
	if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", now, f.admin.SessionID); err != nil {
		t.Fatal(err)
	}
	if result, err := stats(f.admin); err != nil || result.TotalUsers != 1 || result.ActiveSessions != 1 {
		t.Fatalf("admin stats: %+v, %v", result, err)
	}
	f.request(t, "GET", "/admin/stats", "", f.token, 200)
	account, err := f.a.Register(ctx, api.RegisterInput{Email: "stats-operator@example.com", Name: "Stats operator", Password: "Passw0rd!"})
	if err != nil {
		t.Fatal(err)
	}
	operator := api.AppPermissionActor{UserID: account.User.ID, SessionID: account.Session.ID}
	if _, err := f.a.Services().AppPermissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Create: []string{"goauth.app.stats.read"}}); err != nil {
		t.Fatal(err)
	}
	role, err := f.a.Services().AppPermissions.CreateRole(ctx, api.CreateAppRoleInput{Actor: f.admin, Slug: "stats-reader", Name: "Stats reader", PermissionKeys: []string{"goauth.app.stats.read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Services().AppPermissions.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: operator.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: account.User.AppRoleAssignmentRevision}); err != nil {
		t.Fatal(err)
	}
	if result, err := stats(operator); err != nil || result.TotalUsers != 2 {
		t.Fatalf("delegated stats imposed admin MFA: %+v, %v", result, err)
	}
	f.request(t, "GET", "/admin/stats", "", account.SessionToken, 200)
	if err := f.users.SetTwoFactorEnabled(ctx, operator.UserID, true, now); err != nil {
		t.Fatal(err)
	}
	if result, err := stats(operator); !errors.Is(err, domain.ErrTwoFactorRequired) || result != nil {
		t.Fatalf("delegated stats skipped per-user MFA: %+v, %v", result, err)
	}
	f.request(t, "GET", "/admin/stats", "", account.SessionToken, 403)
	if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", now, operator.SessionID); err != nil {
		t.Fatal(err)
	}
	if result, err := stats(operator); err != nil || result.TotalUsers != 2 {
		t.Fatalf("delegated stats: %+v, %v", result, err)
	}
	f.request(t, "GET", "/admin/stats", "", account.SessionToken, 200)
	if result, err := stats(api.AppPermissionActor{UserID: operator.UserID, SessionID: f.admin.SessionID}); !errors.Is(err, domain.ErrForbidden) || result != nil {
		t.Fatalf("foreign session accepted: %+v, %v", result, err)
	}
	if _, err := f.a.Services().AppPermissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Delete: []string{"goauth.app.stats.read"}}); err != nil {
		t.Fatal(err)
	}
	if result, err := stats(operator); !errors.Is(err, domain.ErrForbidden) || result != nil {
		t.Fatalf("removed stats permission accepted: %+v, %v", result, err)
	}
	f.request(t, "GET", "/admin/stats", "", account.SessionToken, 403)
	if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET is_revoked=true WHERE id=$1", f.admin.SessionID); err != nil {
		t.Fatal(err)
	}
	if result, err := stats(f.admin); !errors.Is(err, domain.ErrSessionExpired) || result != nil {
		t.Fatalf("revoked session accepted: %+v, %v", result, err)
	}
}

func TestAppPermissionsSameRoleAssignmentPreservesAccessRevision(t *testing.T) {
	f := newAppHTTPFixture(t, true, true)
	ctx := t.Context()
	account, err := f.a.Register(ctx, api.RegisterInput{Email: "same-role@example.com", Name: "Same role", Password: "Passw0rd!"})
	if err != nil {
		t.Fatal(err)
	}
	repo := sqlstore.NewAppPermissionsRepository(f.db)
	role, err := repo.RoleByID(ctx, *account.User.AppRoleID)
	if err != nil {
		t.Fatal(err)
	}
	input := api.SetAppUserRoleInput{Actor: f.admin, UserID: account.User.ID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: account.User.AppRoleAssignmentRevision}
	body := `{"roleId":"` + role.ID + `","expectedRoleRevision":1,"expectedAssignmentRevision":1}`
	path := "/admin/authorization/users/" + account.User.ID + "/role"
	if _, err := f.a.Services().AppPermissions.SetUserRole(ctx, input); !errors.Is(err, domain.ErrTwoFactorRequired) {
		t.Fatalf("same-role bypassed assurance: %v", err)
	}
	f.request(t, "PUT", path, body, f.token, 403)
	now := time.Now().UTC()
	if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", now, f.admin.SessionID); err != nil {
		t.Fatal(err)
	}
	access := func() api.AppAccess {
		t.Helper()
		w := f.request(t, "GET", "/auth/access", "", account.SessionToken, 200)
		var result api.AppAccess
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	before := access()
	f.request(t, "PUT", path, body, f.token, 200)
	legacyBody := `{"appRoleId":"` + role.ID + `","expectedRoleRevision":1,"expectedAssignmentRevision":1}`
	f.request(t, "PATCH", "/admin/users/"+account.User.ID+"/role", legacyBody, f.token, 200)
	if err := f.a.Services().Admin.UpdateUserRole(ctx, api.UpdateUserRoleInput{ActorID: f.admin.UserID, ActorSessionID: f.admin.SessionID, UserID: account.User.ID, AppRoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: account.User.AppRoleAssignmentRevision}); err != nil {
		t.Fatal(err)
	}
	after := access()
	if before.Revision != after.Revision || before.AssignmentRevision != after.AssignmentRevision || before.Role.ID != after.Role.ID {
		t.Fatalf("no-op changed exposed access: %+v -> %+v", before, after)
	}
}

func TestAppPermissionsHTTPPromotionRequiresFreshAssurance(t *testing.T) {
	f := newAppHTTPFixture(t, true, true)
	ctx := t.Context()
	now := time.Now().UTC()
	if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", now, f.admin.SessionID); err != nil {
		t.Fatal(err)
	}
	account, err := f.a.Register(ctx, api.RegisterInput{Email: "promoted@example.com", Name: "Promoted", Password: "Passw0rd!"})
	if err != nil {
		t.Fatal(err)
	}
	if account.RequiresTwoFactor || account.Session == nil {
		t.Fatal("baseline signup unexpectedly privileged")
	}
	permissions := f.a.Services().AppPermissions
	if _, err := permissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Create: []string{"goauth.app.users.read"}}); err != nil {
		t.Fatal(err)
	}
	r, err := permissions.CreateRole(ctx, api.CreateAppRoleInput{Actor: f.admin, Slug: "reader", Name: "Reader", PermissionKeys: []string{"goauth.app.users.read"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := permissions.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: account.User.ID, RoleID: r.ID, ExpectedRoleRevision: r.Revision, ExpectedAssignmentRevision: 1}); err != nil {
		t.Fatal(err)
	}
	f.request(t, "GET", "/admin/users", "", account.SessionToken, 200)
	login, err := f.a.Login(ctx, api.LoginInput{Email: account.User.Email, Password: "Passw0rd!"})
	if err != nil || login.RequiresTwoFactor || login.Session == nil {
		t.Fatalf("delegated login imposed admin MFA: %+v %v", login, err)
	}
	if result, err := f.a.Services().Auth.AdminLogin(ctx, api.LoginInput{Email: account.User.Email, Password: "Passw0rd!"}); !errors.Is(err, domain.ErrInvalidCredentials) || result != nil {
		t.Fatalf("delegated role accepted at admin login: %+v %v", result, err)
	}
	adminRole, err := permissions.GetUserRole(ctx, api.GetAppUserRoleInput{Actor: f.admin, UserID: f.admin.UserID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := permissions.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: account.User.ID, RoleID: adminRole.Role.ID, ExpectedRoleRevision: adminRole.Role.Revision, ExpectedAssignmentRevision: 2}); err != nil {
		t.Fatal(err)
	}
	w := f.request(t, "GET", "/admin/users", "", account.SessionToken, 403)
	if !strings.Contains(w.Body.String(), "two_factor_required") {
		t.Fatal("protected admin promotion did not require assurance", w.Body.String())
	}
	login, err = f.a.Login(ctx, api.LoginInput{Email: account.User.Email, Password: "Passw0rd!"})
	if err != nil || !login.RequiresTwoFactor || login.Session != nil {
		t.Fatalf("protected admin login did not challenge: %+v %v", login, err)
	}
	login, err = f.a.Services().Auth.AdminLogin(ctx, api.LoginInput{Email: account.User.Email, Password: "Passw0rd!"})
	if err != nil || !login.RequiresTwoFactor || login.Session != nil {
		t.Fatalf("protected admin endpoint did not challenge: %+v %v", login, err)
	}
}

func TestAppPermissionsHTTPDelegatedRoleMFASettings(t *testing.T) {
	for _, tc := range []struct {
		name     string
		adminMFA bool
		global   bool
		perUser  bool
	}{
		{name: "admin-on/user-off", adminMFA: true},
		{name: "admin-off/user-off"},
		{name: "admin-on/global-user", adminMFA: true, global: true},
		{name: "admin-off/global-user", global: true},
		{name: "admin-on/per-user", adminMFA: true, perUser: true},
		{name: "admin-off/per-user", perUser: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAppHTTPFixture(t, true, tc.adminMFA, WithTwoFactor(TwoFactorConfig{
				DisableAdminTwoFactor: !tc.adminMFA, RequireEmail2FA: tc.global,
			}))
			ctx := t.Context()
			now := time.Now().UTC()
			if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", now, f.admin.SessionID); err != nil {
				t.Fatal(err)
			}
			account, err := f.a.Register(ctx, api.RegisterInput{Email: "delegated-mfa@example.com", Name: "Delegated", Password: "Passw0rd!"})
			if err != nil || account.RequiresTwoFactor != tc.global {
				t.Fatalf("registration MFA: %+v %v", account, err)
			}
			if err := f.users.SetTwoFactorEnabled(ctx, account.User.ID, tc.perUser, now); err != nil {
				t.Fatal(err)
			}
			permissions := f.a.Services().AppPermissions
			if _, err := permissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Create: []string{"goauth.app.users.read"}}); err != nil {
				t.Fatal(err)
			}
			role, err := permissions.CreateRole(ctx, api.CreateAppRoleInput{Actor: f.admin, Slug: "mfa-reader", Name: "Reader", PermissionKeys: []string{"goauth.app.users.read"}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := permissions.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: account.User.ID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: 1}); err != nil {
				t.Fatal(err)
			}
			input := api.LoginInput{Email: account.User.Email, Password: "Passw0rd!"}
			login, err := f.a.Login(ctx, input)
			required := tc.global || tc.perUser
			if err != nil || login.RequiresTwoFactor != required || (login.Session != nil) == required {
				t.Fatalf("delegated password login MFA: %+v %v", login, err)
			}
			if result, err := f.a.Services().Auth.AdminLogin(ctx, input); !errors.Is(err, domain.ErrInvalidCredentials) || result != nil {
				t.Fatalf("delegated role accepted at admin login: %+v %v", result, err)
			}
			// Seed a first-factor session to check live route and direct-call policy.
			session, err := f.a.Services().Session.Create(ctx, api.CreateSessionInput{UserID: account.User.ID})
			if err != nil {
				t.Fatal(err)
			}
			actor := api.AppPermissionActor{UserID: account.User.ID, SessionID: session.Session.ID}
			check := api.CheckAppPermissionInput{Actor: actor, PermissionKey: "goauth.app.users.read"}
			decision, err := permissions.CheckPermission(ctx, check)
			if required {
				if !errors.Is(err, domain.ErrTwoFactorRequired) || decision != nil {
					t.Fatalf("delegated direct call skipped user MFA: %+v %v", decision, err)
				}
				f.request(t, "GET", "/admin/users", "", session.SessionToken, 403)
				if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", now, actor.SessionID); err != nil {
					t.Fatal(err)
				}
			} else if err != nil || !decision.Allowed {
				t.Fatalf("delegated direct call imposed admin MFA: %+v %v", decision, err)
			}
			f.request(t, "GET", "/admin/users", "", session.SessionToken, 200)
			decision, err = permissions.CheckPermission(ctx, check)
			if err != nil || !decision.Allowed {
				t.Fatalf("delegated assured access: %+v %v", decision, err)
			}
		})
	}
}

func TestAppPermissionsHTTPBusinessGuardAndProtectedLegacyPayloads(t *testing.T) {
	f := newAppHTTPFixture(t, true, false)
	ctx := t.Context()
	account, err := f.a.Register(ctx, api.RegisterInput{Email: "business@example.com", Name: "Business", Password: "Passw0rd!"})
	if err != nil {
		t.Fatal(err)
	}
	permissions := f.a.Services().AppPermissions
	p, err := permissions.CreatePermission(ctx, api.CreateAppPermissionInput{Actor: f.admin, Key: "app.posts.delete", Name: "Delete posts"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := permissions.CreateRole(ctx, api.CreateAppRoleInput{Actor: f.admin, Slug: "business-admin", Name: "Admin", PermissionKeys: []string{p.Key}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := permissions.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: account.User.ID, RoleID: r.ID, ExpectedRoleRevision: r.Revision, ExpectedAssignmentRevision: 1}); err != nil {
		t.Fatal(err)
	}
	f.mux.Handle("DELETE /posts/{id}", f.a.RequireAuth(f.a.RequireAppPermission(p.Key)(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) },
	))))
	f.request(t, "DELETE", "/posts/one", "", account.SessionToken, 204)
	f.request(t, "GET", "/admin/users", "", account.SessionToken, 403)
	f.request(t, "POST", "/admin/users", `{"email":"evil@example.com","name":"Evil","password":"Passw0rd!","role":"admin"}`, f.token, 400)
	f.request(t, "PATCH", "/admin/users/"+account.User.ID+"/role", `{"role":"admin"}`, f.token, 400)
	f.request(t, "PUT", "/admin/authorization/roles/"+r.ID+"/permissions", `{"expectedRevision":1}`, f.token, 400)
	f.request(t, "PATCH", "/admin/authorization/roles/not-a-uuid", `{"expectedRevision":1,"name":"x"}`, f.token, 400)
	disabled := false
	if _, err := permissions.UpdatePermission(ctx, api.UpdateAppPermissionInput{Actor: f.admin, PermissionID: p.ID, ExpectedRevision: p.Revision, IsEnabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	f.request(t, "DELETE", "/posts/one", "", account.SessionToken, 403)
	f.request(t, "DELETE", "/posts/one", "", f.token, 403)
	f.request(t, "GET", "/auth/me", "", account.SessionToken, 200)
}

func TestAppPermissionsDisabledCapabilityFailsClosed(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	cfg := f.a.cfg
	cfg.appPermissions = AppPermissionsConfig{}
	a, err := New(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	if a.Services().AppPermissions != nil {
		t.Fatal("disabled capability is typed nil")
	}
	for _, pattern := range []string{routes.AppAccess, routes.AppLibraryPermissions, routes.ListAppRoles, routes.GetAppUserAccess} {
		if _, ok := a.Handler(pattern); ok {
			t.Fatalf("disabled route exposed: %s", pattern)
		}
	}
	w := httptest.NewRecorder()
	a.RequireAppPermission("app.posts.delete")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("disabled guard allowed") })).ServeHTTP(w, httptest.NewRequest("DELETE", "/posts/one", nil))
	if w.Code != 503 {
		t.Fatalf("disabled guard status=%d", w.Code)
	}
}
