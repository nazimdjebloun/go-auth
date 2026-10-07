package service

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// These expectations are independent of the production guards. Every exported
// method must be classified; adding a method cannot silently escape this suite.
var appServicePolicies = map[string]map[string]string{
	"Admin": {
		"GetStats": "stats.read", "GetRegistrationTrend": "stats.read", "GetLoginActivity": "stats.read",
		"ListUsers": "users.read", "CountUsers": "users.read", "GetUserDetail": "users.read",
		"CreateUser": "users.create", "BanUser": "users.ban", "BulkBanUsers": "users.ban",
		"UnbanUser": "users.unban", "BulkUnbanUsers": "users.unban",
		"DeleteUser": "users.delete", "BulkDeleteUsers": "users.delete", "UpdateUserRole": "roles.assign",
		"ListSessions": "sessions.read", "CountSessions": "sessions.read", "ListUserSessions": "sessions.read",
		"RevokeUserSession": "sessions.revoke", "RevokeUserSessions": "sessions.revoke", "BulkRevokeUserSessions": "sessions.revoke",
		"ListAuditLogs": "audit.read", "CountAuditLogs": "audit.read",
	},
	"Invite": {
		"CreateInvite": "invites.create", "BulkSendInvites": "invites.create",
		"ListInvites": "invites.read", "CountInvites": "invites.read",
		"HardDeleteInvite": "invites.delete", "BulkDeleteInvites": "invites.delete",
		"RevokeInvite": "invites.revoke", "BulkRevokeInvites": "invites.revoke",
		"ResendInviteEmail": "invites.resend", "BulkResendInvites": "invites.resend",
	},
	"Org": {
		"AdminListOrgs": "protected", "CountOrgs": "protected", "AdminGetOrg": "protected",
		"AdminListUserOrgs": "protected", "AdminCountUserOrgs": "protected",
		"AdminListOrgMembers": "protected", "AdminCountOrgMembers": "protected",
		"AdminDeleteOrg": "protected", "AdminAddMember": "protected", "AdminRemoveMember": "protected", "AdminUpdateMemberRole": "protected",
	},
	"AppPermissions": {
		"CreatePermission": "permissions.create", "UpdatePermission": "permissions.update",
		"DeletePermission": "permissions.delete", "ListPermissions": "permissions.read",
		"CreateRole": "roles.create", "UpdateRole": "roles.update", "SetRolePermissions": "roles.update",
		"DeleteRole": "roles.delete", "ListRoles": "roles.read", "GetUserRole": "roles.read",
		"SetUserRole": "roles.assign", "ListEffectivePermissions": "roles.read",
		"UpdateLibraryPermissions": "protected", "RequireProtectedAdmin": "protected",
	},
}

var appServiceExemptions = map[string]map[string]string{
	"Admin": {"AttachAccountDeletion": "construction-only dependency wiring"},
	"Invite": {
		"GetInviteByToken":           "public invite-token redemption lookup",
		"CompleteInviteRegistration": "public invite-token redemption",
	},
	"Org": {
		"CreateOrg": "tenant self-service", "GetByID": "tenant membership", "GetBySlug": "tenant membership",
		"UpdateOrg": "tenant administration", "DeleteOrg": "tenant ownership", "ListUserOrgs": "own memberships",
		"GetMembership": "tenant membership", "AddMember": "tenant administration", "RemoveMember": "tenant administration",
		"UpdateMemberRole": "tenant administration", "LeaveOrg": "own membership", "ListMembers": "tenant membership",
		"SetActiveOrg": "own session", "ClearActiveOrg": "own session", "CountMembers": "tenant membership", "CountUserOrgs": "own memberships",
	},
	"AppPermissions": {
		"Initialize":               "trusted installation bootstrap; not a runtime administrative action",
		"AssignBaseline":           "internal transactional signup coordinator",
		"AssignCreatedRole":        "internal guarded creation coordinator; explicit roles separately require roles.assign",
		"IsProtectedAdmin":         "informational identity lookup",
		"HasAdministrativeAccess":  "informational MFA-policy lookup",
		"CheckPermission":          "caller-selected permission guard",
		"RequirePermission":        "caller-selected permission guard",
		"LibraryPermissionCatalog": "fixed catalog lookup; HTTP has a separate protected guard",
	},
}

func TestAppAuthorizationServiceInventory(t *testing.T) {
	types := map[string]reflect.Type{
		"Admin": reflect.TypeFor[*AdminService](), "Invite": reflect.TypeFor[*InviteService](),
		"Org": reflect.TypeFor[*OrgService](), "AppPermissions": reflect.TypeFor[*AppPermissionsService](),
	}
	used := map[string]bool{}
	for group, typ := range types {
		t.Run(group, func(t *testing.T) {
			for index := range typ.NumMethod() {
				name := typ.Method(index).Name
				key, covered := appServicePolicies[group][name]
				reason, exempt := appServiceExemptions[group][name]
				if covered == exempt || (exempt && reason == "") {
					t.Errorf("%s.%s needs exactly one explicit policy or documented exemption", group, name)
				}
				if covered && key != "protected" {
					if _, known := appLibraryDefinition("goauth.app." + key); !known {
						t.Errorf("%s.%s maps to unknown catalog key %s", group, name, key)
					}
					used["goauth.app."+key] = true
				}
			}
			for _, classified := range []map[string]string{appServicePolicies[group], appServiceExemptions[group]} {
				for name := range classified {
					if _, exists := typ.MethodByName(name); !exists {
						t.Errorf("stale classification: %s.%s", group, name)
					}
				}
			}
		})
	}
	for _, definition := range AppLibraryPermissionCatalog() {
		if !used[definition.Key] {
			t.Errorf("catalog key %s has no covered service operation", definition.Key)
		}
	}
}

var errAppCoverageProbe = errors.New("authorization coverage lookup probe")

type appCoverageReader struct {
	port.AppPermissionReader
	keys []string
	stop bool
}

func (r *appCoverageReader) PermissionByKey(ctx context.Context, key string) (*domain.AppPermission, error) {
	r.keys = append(r.keys, key)
	if r.stop {
		return nil, errAppCoverageProbe
	}
	return r.AppPermissionReader.PermissionByKey(ctx, key)
}

// Valid inputs keep validation errors from masquerading as authorization denial.
// Reflection makes every inventoried method executable without a second list
// of wrappers that could omit a newly classified operation.
func appCoverageCall(t *testing.T, receiver any, name string, actor api.AppPermissionActor) error {
	t.Helper()
	method := reflect.ValueOf(receiver).MethodByName(name)
	if !method.IsValid() || method.Type().NumIn() != 2 {
		t.Fatalf("coverage requires a context and input for %T.%s", receiver, name)
	}
	input := reflect.New(method.Type().In(1)).Elem()
	if input.Type() == reflect.TypeFor[api.AppPermissionActor]() {
		input.Set(reflect.ValueOf(actor))
	} else {
		target := "00000000-0000-4000-8000-000000000001"
		for fieldName, value := range map[string]string{
			"ActorID": actor.UserID, "AdminID": actor.UserID, "ActorSessionID": actor.SessionID,
			"UserID": target, "RoleID": target, "AppRoleID": target, "PermissionID": target,
			"InviteID": target, "OrgID": target, "SessionID": target,
			"Key": "app.coverage.create", "Name": "Coverage", "Slug": "coverage", "Email": "coverage@example.com", "Password": "Passw0rd!",
		} {
			if field := input.FieldByName(fieldName); field.IsValid() && field.Kind() == reflect.String {
				field.SetString(value)
			}
		}
		if field := input.FieldByName("Actor"); field.IsValid() {
			field.Set(reflect.ValueOf(actor))
		}
		for _, fieldName := range []string{"Role", "NewRole"} {
			if field := input.FieldByName(fieldName); field.IsValid() && field.Type() == reflect.TypeFor[domain.OrgRole]() {
				field.SetString("member")
			}
		}
		for _, fieldName := range []string{"ExpectedRevision", "ExpectedRoleRevision", "ExpectedAssignmentRevision"} {
			if field := input.FieldByName(fieldName); field.IsValid() {
				field.SetUint(1)
			}
		}
		for _, fieldName := range []string{"UserIDs", "InviteIDs", "Emails", "Create"} {
			if field := input.FieldByName(fieldName); field.IsValid() {
				value := target
				if fieldName == "Emails" {
					value = "coverage@example.com"
				}
				if fieldName == "Create" {
					value = "goauth.app.users.read"
				}
				field.Set(reflect.ValueOf([]string{value}))
			}
		}
		for _, fieldName := range []string{"From", "To"} {
			if field := input.FieldByName(fieldName); field.IsValid() {
				field.Set(reflect.ValueOf(time.Now().UTC()))
			}
		}
	}
	results := method.Call([]reflect.Value{reflect.ValueOf(t.Context()), input})
	last := results[len(results)-1]
	if last.Type() != reflect.TypeFor[error]() {
		t.Fatalf("%T.%s must end in an error", receiver, name)
	}
	if last.IsNil() {
		return nil
	}
	return last.Interface().(error)
}

func TestAppAuthorizationServiceCoverage(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	delegate := f.account(t)
	keys := []string{}
	for _, definition := range AppLibraryPermissionCatalog() {
		keys = append(keys, definition.Key)
	}
	f.install(t, keys...)
	role := f.role(t, "coverage-operator", keys...)
	f.assign(t, delegate, role)
	baseline := f.account(t)
	for _, actor := range []*api.AppPermissionActor{&f.admin, &delegate, &baseline} {
		result, err := f.s.sessionSvc.Create(ctx, api.CreateSessionInput{UserID: actor.UserID})
		if err != nil {
			t.Fatal(err)
		}
		actor.SessionID = result.Session.ID
		if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", time.Now().UTC(), actor.SessionID); err != nil {
			t.Fatal(err)
		}
	}
	f.s.config.RequireAdminTwoFactor = true
	beforeRevision, err := f.repo.AppStateRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reader := &appCoverageReader{AppPermissionReader: f.repo}
	f.s.permissions = reader
	// Business dependencies are deliberately absent: a missing guard fails the
	// test before it can mutate data or send email, including bulk operations.
	cfg := defaultTestConfig()
	cfg.AppPermissions, cfg.EnableInvite = f.s, true
	services := map[string]any{
		"Admin":          NewAdminService(f.db, nil, nil, nil, nil, nil, cfg, nil),
		"Invite":         NewInviteService(nil, nil, nil, nil, nil, nil, f.db, cfg, nil, nil),
		"Org":            NewOrgService(nil, nil, nil, f.db, OrgServiceConfig{AppPermissions: f.s}),
		"AppPermissions": f.s,
	}
	for group, policies := range appServicePolicies {
		for name, key := range policies {
			t.Run(group+"/"+name, func(t *testing.T) {
				for _, scenario := range []struct {
					name  string
					actor api.AppPermissionActor
					want  error
				}{
					{"no_grants", baseline, domain.ErrForbidden},
					{"missing_actor", api.AppPermissionActor{}, domain.ErrForbidden},
					{"missing_assurance", api.AppPermissionActor{UserID: f.admin.UserID}, domain.ErrTwoFactorRequired},
					{"foreign_session", api.AppPermissionActor{UserID: f.admin.UserID, SessionID: delegate.SessionID}, domain.ErrForbidden},
				} {
					t.Run(scenario.name, func(t *testing.T) {
						reader.stop, reader.keys = false, nil
						if err := appCoverageCall(t, services[group], name, scenario.actor); !errors.Is(err, scenario.want) {
							t.Fatalf("got %v, want %v", err, scenario.want)
						}
					})
				}
				t.Run("exact_policy_and_infrastructure_failure", func(t *testing.T) {
					reader.stop, reader.keys = true, nil
					want := errAppCoverageProbe
					if key == "protected" {
						want = domain.ErrForbidden
					}
					err := appCoverageCall(t, services[group], name, delegate)
					if !errors.Is(err, want) {
						t.Fatalf("got %v, want %v", err, want)
					}
					expected := []string(nil)
					if key != "protected" {
						expected = []string{"goauth.app." + key}
					}
					if !slices.Equal(reader.keys, expected) {
						t.Fatalf("checked %v, want %v", reader.keys, expected)
					}
				})
			})
		}
	}
	reader.stop = false
	for _, scenario := range []struct {
		name, query, target string
		want                error
	}{
		{"revoked_session", "UPDATE sessions SET is_revoked=true WHERE id=$1", f.admin.SessionID, domain.ErrSessionExpired},
		{"expired_session", "UPDATE sessions SET is_revoked=false,expires_at=$1 WHERE id=$2", f.admin.SessionID, domain.ErrSessionExpired},
		{"removed_assurance", "UPDATE sessions SET expires_at=$1,two_factor_verified_at=NULL WHERE id=$2", f.admin.SessionID, domain.ErrTwoFactorRequired},
		{"deleted_session", "DELETE FROM sessions WHERE id=$1", f.admin.SessionID, domain.ErrForbidden},
		{"banned_actor", "UPDATE users SET is_banned=true WHERE id=$1", f.admin.UserID, domain.ErrForbidden},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if scenario.name == "banned_actor" {
				// Use a live assured session so deletion in the preceding case
				// cannot accidentally supply this case's expected denial.
				result, err := f.s.sessionSvc.Create(ctx, api.CreateSessionInput{UserID: f.admin.UserID})
				if err != nil {
					t.Fatal(err)
				}
				f.admin.SessionID = result.Session.ID
				if _, err := f.db.ExecContext(ctx, "UPDATE sessions SET two_factor_verified_at=$1 WHERE id=$2", time.Now().UTC(), f.admin.SessionID); err != nil {
					t.Fatal(err)
				}
			}
			args := []any{scenario.target}
			if scenario.name == "expired_session" {
				args = []any{time.Now().UTC().Add(-time.Hour), scenario.target}
			}
			if scenario.name == "removed_assurance" {
				args = []any{time.Now().UTC().Add(time.Hour), scenario.target}
			}
			if _, err := f.db.ExecContext(ctx, scenario.query, args...); err != nil {
				t.Fatal(err)
			}
			for group, policies := range appServicePolicies {
				for name := range policies {
					t.Run(group+"/"+name, func(t *testing.T) {
						if err := appCoverageCall(t, services[group], name, f.admin); !errors.Is(err, scenario.want) {
							t.Fatalf("got %v, want %v", err, scenario.want)
						}
					})
				}
			}
		})
	}
	if _, err := f.db.ExecContext(ctx, "UPDATE users SET is_banned=false WHERE id=$1", f.admin.UserID); err != nil {
		t.Fatal(err)
	}
	admin, err := f.users.GetByID(ctx, f.admin.UserID)
	if err != nil || admin == nil || admin.AppRoleID == nil {
		t.Fatalf("admin identity: %+v %v", admin, err)
	}
	if _, err := f.db.ExecContext(ctx, "UPDATE app_roles SET is_enabled=false WHERE id=$1", *admin.AppRoleID); err != nil {
		t.Fatal(err)
	}
	t.Run("disabled_role", func(t *testing.T) {
		for group, policies := range appServicePolicies {
			for name := range policies {
				t.Run(group+"/"+name, func(t *testing.T) {
					if err := appCoverageCall(t, services[group], name, f.admin); !errors.Is(err, domain.ErrForbidden) {
						t.Fatalf("got %v, want forbidden", err)
					}
				})
			}
		}
	})
	afterRevision, err := f.repo.AppStateRevision(ctx)
	if err != nil || afterRevision != beforeRevision {
		t.Fatalf("denied calls changed state revision: %d -> %d: %v", beforeRevision, afterRevision, err)
	}
}
