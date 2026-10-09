package goauth

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/handler"
	"github.com/nazimdjebloun/go-auth/internal/httproutes"
	"github.com/nazimdjebloun/go-auth/internal/routes"
	"github.com/nazimdjebloun/go-auth/internal/service"
)

// Independent expectations: production route registration must not define its
// own expected policy. Organization oversight and provisioning stay protected.
var appRoutePolicies = map[string]string{
	routes.ListUsers: "users.read", routes.AdminCountUsers: "users.read", routes.GetUserDetail: "users.read",
	routes.AdminCreateUser: "users.create", routes.UpdateUserRole: "roles.assign",
	routes.BanUser: "users.ban", routes.UnbanUser: "users.unban", routes.DeleteUser: "users.delete",
	routes.BulkBanUsers: "users.ban", routes.BulkUnbanUsers: "users.unban", routes.BulkDeleteUsers: "users.delete",
	routes.AdminListSessions: "sessions.read", routes.AdminCountSessions: "sessions.read", routes.AdminListUserSessions: "sessions.read",
	routes.AdminRevokeUserSession: "sessions.revoke", routes.RevokeUserSessions: "sessions.revoke", routes.BulkRevokeUserSessions: "sessions.revoke",
	routes.AdminListAuditLogs: "audit.read", routes.AdminCountAuditLogs: "audit.read",
	routes.AdminListUserAuditLogs: "audit.read", routes.AdminCountUserAuditLogs: "audit.read",
	routes.AdminStats: "stats.read", routes.AdminRegistrationTrend: "stats.read", routes.AdminLoginActivity: "stats.read",
	routes.CreateInvite: "invites.create", routes.BulkSendInvites: "invites.create",
	routes.ListInvites: "invites.read", routes.AdminCountInvites: "invites.read",
	routes.RevokeInvite: "invites.revoke", routes.BulkRevokeInvites: "invites.revoke",
	routes.HardDeleteInvite: "invites.delete", routes.BulkDeleteInvites: "invites.delete",
	routes.ResendInvite: "invites.resend", routes.BulkResendInvites: "invites.resend",
	routes.ListAppPermissions: "permissions.read", routes.CreateAppPermission: "permissions.create",
	routes.UpdateAppPermission: "permissions.update", routes.DeleteAppPermission: "permissions.delete",
	routes.ListAppRoles: "roles.read", routes.CreateAppRole: "roles.create", routes.UpdateAppRole: "roles.update",
	routes.SetAppRolePermissions: "roles.update", routes.DeleteAppRole: "roles.delete",
	routes.GetAppUserRole: "roles.read", routes.GetAppUserAccess: "roles.read", routes.SetAppUserRole: "roles.assign",
	routes.AppLibraryPermissions: "protected", routes.UpdateAppLibraryPermissions: "protected",
	routes.AdminListOrgs: "protected", routes.AdminCountOrgs: "protected", routes.AdminGetOrg: "protected",
	routes.AdminListOrgMembers: "protected", routes.AdminCountOrgMembers: "protected",
	routes.AdminAddOrgMember: "protected", routes.AdminDeleteOrg: "protected",
	routes.AdminRemoveOrgMember: "protected", routes.AdminUpdateOrgMemberRole: "protected",
	routes.AdminListUserOrgs: "protected", routes.AdminCountUserOrgs: "protected",
}

func appIsAdministrativeRoute(pattern string) bool {
	_, path, _ := strings.Cut(pattern, " ")
	return path == "/admin" || strings.HasPrefix(path, "/admin/")
}

func appDeclaredAdminRoutes(t *testing.T) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "internal/routes/routes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	constants := map[string]string{}
	var value func(ast.Expr) string
	value = func(expr ast.Expr) string {
		switch expr := expr.(type) {
		case *ast.BasicLit:
			result, err := strconv.Unquote(expr.Value)
			if err != nil {
				t.Fatal(err)
			}
			return result
		case *ast.BinaryExpr:
			if expr.Op == token.ADD {
				return value(expr.X) + value(expr.Y)
			}
		case *ast.Ident:
			if result, found := constants[expr.Name]; found {
				return result
			}
		case *ast.ParenExpr:
			return value(expr.X)
		}
		t.Fatalf("unsupported route constant expression %T; update discovery explicitly", expr)
		return ""
	}
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST {
			continue
		}
		for _, spec := range group.Specs {
			item := spec.(*ast.ValueSpec)
			if len(item.Names) != len(item.Values) {
				t.Fatal("route constants must have explicit values")
			}
			for index, name := range item.Names {
				constants[name.Name] = value(item.Values[index])
			}
		}
	}
	result := map[string]bool{}
	for _, pattern := range constants {
		if appIsAdministrativeRoute(pattern) {
			result[pattern] = true
		}
	}
	return result
}

func appRouteEnabled(pattern string, features httproutes.Features) bool {
	switch {
	case strings.Contains(pattern, "/admin/authorization/"):
		return features.AppPermissionManagement
	case strings.Contains(pattern, "/admin/invites"):
		return features.Invite
	case strings.Contains(pattern, "/admin/orgs") || strings.HasSuffix(pattern, "/orgs") || strings.HasSuffix(pattern, "/orgs/count"):
		return features.Organizations
	default:
		return true
	}
}

func TestAppAuthorizationRouteInventory(t *testing.T) {
	for _, test := range []struct {
		name, pattern string
		want          bool
	}{
		{"root", "GET /admin", true},
		{"descendant", "POST /admin/users", true},
		{"similar_prefix", "GET /administrator", false},
		{"login", "POST /auth/admin/login", false},
		{"tenant_path", "GET /auth/orgs/admin", false},
	} {
		t.Run("namespace/"+test.name, func(t *testing.T) {
			if got := appIsAdministrativeRoute(test.pattern); got != test.want {
				t.Fatalf("administrative=%v want=%v for %s", got, test.want, test.pattern)
			}
		})
	}
	declared := appDeclaredAdminRoutes(t)
	for pattern := range declared {
		if _, covered := appRoutePolicies[pattern]; !covered {
			t.Errorf("unclassified administrative route: %s", pattern)
		}
	}
	used := map[string]bool{}
	catalog := map[string]bool{}
	for _, definition := range service.AppLibraryPermissionCatalog() {
		catalog[definition.Key] = true
	}
	for pattern, policy := range appRoutePolicies {
		if !declared[pattern] {
			t.Errorf("stale route policy: %s", pattern)
		}
		if policy != "protected" {
			key := "goauth.app." + policy
			if !catalog[key] {
				t.Errorf("%s uses unknown key %s", pattern, key)
			}
			used[key] = true
		}
	}
	for key := range catalog {
		if !used[key] {
			t.Errorf("catalog key %s has no covered administrative route", key)
		}
	}
}

func TestAppAuthorizationRouteCoverage(t *testing.T) {
	var trace []string
	wrap := func(label string, stop bool) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				trace = append(trace, label)
				if stop {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	}
	mw := httproutes.Middleware{
		CORS: wrap("cors", false), RateLimit: wrap("rate", false),
		CSRFToken: wrap("csrf-token", false), CSRF: wrap("csrf", false), Auth: wrap("auth", false),
		Admin: wrap("protected", true), OrgMember: wrap("member", false), OrgAdmin: wrap("org-admin", false), OrgOwner: wrap("owner", false),
		AppOperation: func(key string) func(http.Handler) http.Handler { return wrap(key, true) },
	}
	// Exercise every feature combination, including optional invite, organization,
	// OAuth and management groups. An added feature field must be classified too.
	if reflect.TypeFor[httproutes.Features]().NumField() != 6 {
		t.Fatal("classify new HTTP features in authorization coverage")
	}
	for mask := range 64 {
		features := httproutes.Features{AppPermissions: mask&1 != 0, AppPermissionManagement: mask&2 != 0, EmailRegistration: mask&4 != 0, Invite: mask&8 != 0, OAuth: mask&16 != 0, Organizations: mask&32 != 0}
		t.Run(strconv.Itoa(mask), func(t *testing.T) {
			seen := map[string]bool{}
			for _, entry := range httproutes.Build(features, &handler.Handler{}, &handler.OAuthHandlers{}, mw) {
				if !appIsAdministrativeRoute(entry.Pattern) {
					continue
				}
				policy, covered := appRoutePolicies[entry.Pattern]
				if !covered {
					t.Fatalf("unclassified registered admin route %s", entry.Pattern)
				}
				if seen[entry.Pattern] {
					t.Fatalf("duplicate route %s", entry.Pattern)
				}
				seen[entry.Pattern] = true
				t.Run(entry.Pattern, func(t *testing.T) {
					method, path, _ := strings.Cut(entry.Pattern, " ")
					trace = nil
					w := httptest.NewRecorder()
					entry.Handler.ServeHTTP(w, httptest.NewRequest(method, path, nil))
					expected := []string{"cors", "rate"}
					if method != "GET" {
						expected = append(expected, "csrf-token", "csrf")
					}
					expected = append(expected, "auth")
					if policy != "protected" {
						policy = "goauth.app." + policy
					}
					expected = append(expected, policy)
					if w.Code != 204 || !slices.Equal(trace, expected) {
						t.Fatalf("chain=%v status=%d, want %v and terminal authorization guard", trace, w.Code, expected)
					}
				})
			}
			for pattern := range appRoutePolicies {
				if seen[pattern] != appRouteEnabled(pattern, features) {
					t.Errorf("route %s availability=%v for %+v", pattern, seen[pattern], features)
				}
			}
		})
	}
}

func TestAppAuthorizationHTTPPolicyMatrix(t *testing.T) {
	f := newAppHTTPFixture(t, true, true)
	ctx := t.Context()
	verify := func(id string, verified bool) {
		t.Helper()
		var stamp any
		if verified {
			stamp = time.Now().UTC()
		}
		if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", stamp, id); err != nil {
			t.Fatal(err)
		}
	}
	verify(f.admin.SessionID, true)
	permissions := f.a.Services().AppPermissions
	keys := []string{}
	for _, definition := range service.AppLibraryPermissionCatalog() {
		keys = append(keys, definition.Key)
	}
	if _, err := permissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Create: keys}); err != nil {
		t.Fatal(err)
	}
	account, err := f.a.Register(ctx, api.RegisterInput{Email: "coverage@example.com", Name: "Coverage", Password: "Passw0rd!"})
	if err != nil {
		t.Fatal(err)
	}
	verify(account.Session.ID, true)
	for _, change := range []struct {
		id        string
		fixedRole domain.Role
	}{{f.admin.UserID, domain.RoleUser}, {account.User.ID, domain.RoleAdmin}} {
		if _, err := f.db.ExecContext(ctx, "UPDATE users SET role=$1 WHERE id=$2", change.fixedRole, change.id); err != nil {
			t.Fatal(err)
		}
	}
	role, err := permissions.CreateRole(ctx, api.CreateAppRoleInput{Actor: f.admin, Slug: "coverage", Name: "Coverage"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := permissions.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: account.User.ID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: 1}); err != nil {
		t.Fatal(err)
	}
	setGrants := func(grants ...string) {
		t.Helper()
		current, err := permissions.GetUserRole(ctx, api.GetAppUserRoleInput{Actor: f.admin, UserID: account.User.ID})
		if err != nil {
			t.Fatal(err)
		}
		role = &current.Role
		role, err = permissions.SetRolePermissions(ctx, api.SetAppRolePermissionsInput{Actor: f.admin, RoleID: role.ID, ExpectedRevision: role.Revision, PermissionKeys: grants})
		if err != nil {
			t.Fatal(err)
		}
	}
	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	identity := func(next http.Handler) http.Handler { return next }
	// Test the actual registered guard with an observable terminal in place of
	// business work. This proves allow as well as deny without creating/deleting
	// accounts or sending email for every permission combination.
	mw := httproutes.Middleware{CORS: identity, RateLimit: identity, CSRFToken: identity, CSRF: identity,
		Auth: f.a.RequireAuth, OrgMember: identity, OrgAdmin: identity, OrgOwner: identity,
		Admin: func(http.Handler) http.Handler { return f.a.RequireAdmin(terminal) },
		AppOperation: func(key string) func(http.Handler) http.Handler {
			return func(http.Handler) http.Handler { return f.a.RequireAppPermission(key)(terminal) }
		},
	}
	entries := httproutes.Build(httproutes.Features{AppPermissions: true, AppPermissionManagement: true, Invite: true, Organizations: true}, &handler.Handler{}, nil, mw)
	check := func(t *testing.T, token string, want int, policy string, codes ...string) {
		t.Helper()
		for _, entry := range entries {
			if !appIsAdministrativeRoute(entry.Pattern) {
				continue
			}
			if policy != "" && appRoutePolicies[entry.Pattern] != policy {
				continue
			}
			t.Run(entry.Pattern, func(t *testing.T) {
				method, path, _ := strings.Cut(entry.Pattern, " ")
				r := httptest.NewRequest(method, path, nil)
				if token != "" {
					r.Header.Set("Cookie", f.a.cfg.cookie.Name+"="+token)
				}
				w := httptest.NewRecorder()
				entry.Handler.ServeHTTP(w, r)
				if w.Code != want {
					t.Fatalf("status=%d want=%d: %s", w.Code, want, w.Body.String())
				}
				code := ""
				if want == 403 {
					code = "forbidden"
				}
				if len(codes) != 0 {
					code = codes[0]
				}
				if code != "" {
					var result struct {
						Error string `json:"error"`
					}
					if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Error != code {
						t.Fatalf("error=%s want=%s: %v", w.Body.String(), code, err)
					}
				}
			})
		}
	}
	t.Run("unauthenticated", func(t *testing.T) { check(t, "", 401, "") })
	t.Run("no_grants", func(t *testing.T) { check(t, account.SessionToken, 403, "") })
	t.Run("protected_admin", func(t *testing.T) { check(t, f.token, 204, "") })
	verify(f.admin.SessionID, false)
	t.Run("protected_admin_missing_assurance", func(t *testing.T) { check(t, f.token, 403, "", "two_factor_required") })
	verify(f.admin.SessionID, true)
	for index, key := range keys {
		policy := strings.TrimPrefix(key, "goauth.app.")
		t.Run(policy, func(t *testing.T) {
			setGrants(key)
			t.Run("exact_grant", func(t *testing.T) { check(t, account.SessionToken, 204, policy) })
			verify(account.Session.ID, false)
			t.Run("user_mfa_off", func(t *testing.T) { check(t, account.SessionToken, 204, policy) })
			if err := f.users.SetTwoFactorEnabled(ctx, account.User.ID, true, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			t.Run("user_mfa_missing_assurance", func(t *testing.T) { check(t, account.SessionToken, 403, policy, "two_factor_required") })
			verify(account.Session.ID, true)
			t.Run("user_mfa_verified", func(t *testing.T) { check(t, account.SessionToken, 204, policy) })
			if err := f.users.SetTwoFactorEnabled(ctx, account.User.ID, false, time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			setGrants(keys[(index+1)%len(keys)])
			t.Run("wrong_grant", func(t *testing.T) { check(t, account.SessionToken, 403, policy) })
			setGrants(key)
			if _, err := permissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Delete: []string{key}}); err != nil {
				t.Fatal(err)
			}
			t.Run("removed_definition", func(t *testing.T) { check(t, account.SessionToken, 403, policy) })
			if _, err := permissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Create: []string{key}}); err != nil {
				t.Fatal(err)
			}
			t.Run("reinstalled_without_grant", func(t *testing.T) { check(t, account.SessionToken, 403, policy) })
		})
	}
	setGrants(keys...)
	t.Run("all_grants_cannot_delegate_protected_routes", func(t *testing.T) { check(t, account.SessionToken, 403, "protected") })
	verify(f.admin.SessionID, false)
	t.Run("protected_admin_missing_assurance", func(t *testing.T) { check(t, f.token, 403, "", "two_factor_required") })
	verify(f.admin.SessionID, true)
	if _, err := permissions.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Delete: keys}); err != nil {
		t.Fatal(err)
	}
	t.Run("protected_admin_without_installed_definitions", func(t *testing.T) { check(t, f.token, 204, "") })
	if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET is_revoked=true WHERE id=$1", f.admin.SessionID); err != nil {
		t.Fatal(err)
	}
	t.Run("revoked_admin_session", func(t *testing.T) { check(t, f.token, 401, "") })
}

func TestAppAuthorizationMountedRoutesDenyUnprivileged(t *testing.T) {
	f := newAppHTTPFixture(t, true, true, WithOrganizations(OrganizationConfig{Enable: true}))
	account, err := f.a.Register(t.Context(), api.RegisterInput{Email: "mounted-coverage@example.com", Name: "Coverage", Password: "Passw0rd!"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(t.Context(), "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", time.Now().UTC(), account.Session.ID); err != nil {
		t.Fatal(err)
	}
	for pattern := range appRoutePolicies {
		t.Run(pattern, func(t *testing.T) {
			if _, mounted := f.a.Handler(pattern); !mounted {
				t.Fatalf("admin route not mounted: %s", pattern)
			}
			method, path, _ := strings.Cut(pattern, " ")
			for _, segment := range strings.Split(path, "/") {
				if strings.HasPrefix(segment, "{") {
					path = strings.ReplaceAll(path, segment, "00000000-0000-4000-8000-000000000001")
				}
			}
			w := f.request(t, method, path, `{}`, account.SessionToken, 403)
			var result struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Error != "forbidden" {
				t.Fatalf("denial=%s: %v", w.Body.String(), err)
			}
		})
	}
}
