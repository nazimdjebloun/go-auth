package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func TestGetActorValidatesCurrentSessionAndAccount(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, appHTTPFixture) string
		want   error
	}{
		{name: "valid"},
		{name: "missing credential", change: func(*testing.T, appHTTPFixture) string { return "" }, want: domain.ErrSessionExpired},
		{name: "invalid credential", change: func(*testing.T, appHTTPFixture) string { return "invalid" }, want: domain.ErrSessionExpired},
		{name: "expired", change: func(t *testing.T, f appHTTPFixture) string {
			if _, err := f.db.ExecContext(t.Context(), "UPDATE sessions SET expires_at = $1 WHERE id = $2", time.Now().Add(-time.Hour), f.admin.SessionID); err != nil {
				t.Fatal(err)
			}
			return f.token
		}, want: domain.ErrSessionExpired},
		{name: "revoked", change: func(t *testing.T, f appHTTPFixture) string {
			if err := f.a.Trusted().Session.RevokeByID(t.Context(), f.admin.SessionID); err != nil {
				t.Fatal(err)
			}
			return f.token
		}, want: domain.ErrSessionExpired},
		{name: "banned", change: func(t *testing.T, f appHTTPFixture) string {
			if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET is_banned = $1 WHERE id = $2", true, f.admin.UserID); err != nil {
				t.Fatal(err)
			}
			return f.token
		}, want: domain.ErrUserBanned},
		{name: "verification now required", change: func(t *testing.T, f appHTTPFixture) string {
			if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET is_verified = $1 WHERE id = $2", false, f.admin.UserID); err != nil {
				t.Fatal(err)
			}
			return f.token
		}, want: domain.ErrEmailNotVerified},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAppHTTPFixture(t, false, false, WithRegistration(RegistrationConfig{EmailPassword: true, AllowPublic: true, RequireEmailVerification: true}))
			token := f.token
			if test.change != nil {
				token = test.change(t, f)
			}
			actor, err := f.a.GetActor(t.Context(), token)
			if !errors.Is(err, test.want) {
				t.Fatalf("error=%v want %v", err, test.want)
			}
			if err != nil && actor != (api.Actor{}) {
				t.Fatal("failed authentication returned partial identity")
			}
			if err == nil && actor != f.admin {
				t.Fatalf("actor=%+v want %+v", actor, f.admin)
			}
		})
	}
}

// The same consumer service is used by HTTP and a custom backend entry point.
// Its repository only receives the scope returned by the CURRENT permission check.
type actorRecordService struct {
	auth    *Auth
	records tenantRecordStore
	reads   int
}

func (s *actorRecordService) Read(ctx context.Context, actor api.OrgPermissionActor, id string) (string, error) {
	scope, err := s.auth.AuthorizeOrg(ctx, api.CheckOrgPermissionInput{Actor: actor, PermissionKey: "org.records.read"})
	if err != nil {
		return "", err
	}
	s.reads++
	value, found := s.records.get(ctx, scope, id)
	if !found {
		return "", errors.New("record not found")
	}
	return value, nil
}

func TestActorScopeAcrossHTTPAndBackendServices(t *testing.T) {
	f := newAppHTTPFixture(t, true, false, WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true}))
	member := registerForScopedRoute(t, f.a, "actor-member@example.test")
	orgs := make([]*domain.Organization, 0, 2)
	var roleA *domain.OrgPermissionRole
	for range 2 {
		org, err := f.a.Trusted().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Tenant", Slug: uuid.NewString()})
		if err != nil {
			t.Fatal(err)
		}
		owner := f.admin.ForOrg(org.ID)
		if _, err := f.a.Services().OrgPermissions.CreatePermission(t.Context(), api.CreateOrgPermissionInput{Actor: owner, Key: "org.records.read", Name: "Read records"}); err != nil {
			t.Fatal(err)
		}
		if err := f.a.Services().Org.AddMember(t.Context(), api.AddMemberInput{OrgID: org.ID, UserID: member.User.ID, Role: domain.OrgRoleMember, ActorID: owner.UserID, ActorSessionID: owner.SessionID}); err != nil {
			t.Fatal(err)
		}
		role, err := f.a.Services().OrgPermissions.CreateRole(t.Context(), api.CreateOrgRoleInput{Actor: owner, Slug: "reader", Name: "Reader", PermissionKeys: []string{"org.records.read"}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.a.Services().OrgPermissions.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: owner, UserID: member.User.ID, RoleID: role.ID, ExpectedRoleRevision: role.Revision}); err != nil {
			t.Fatal(err)
		}
		if roleA == nil {
			roleA = role
		}
		orgs = append(orgs, org)
	}
	orgA, orgB := orgs[0].ID, orgs[1].ID
	service := &actorRecordService{auth: f.a, records: tenantRecordStore{orgA: {"shared-id": "A"}, orgB: {"shared-id": "B"}}}
	var received OrgScope
	handler := func(w http.ResponseWriter, r *http.Request, scope OrgScope) {
		received = scope
		actor, ok := middleware.ActorFromContext(r.Context())
		if !ok || actor != scope.Actor() {
			t.Error("HTTP actor and org scope disagree")
		}
		value, err := service.Read(r.Context(), scope.PermissionActor(), r.PathValue("recordID"))
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		if err := json.NewEncoder(w).Encode(map[string]string{"value": value}); err != nil {
			t.Error(err)
		}
	}
	pattern := "GET /actor-records/{orgID}/{recordID}"
	f.mux.Handle(pattern, f.a.ProtectOrgScope(pattern, "org.records.read", handler))
	activePattern := "GET /actor-active/{recordID}"
	f.mux.Handle(activePattern, f.a.ProtectActiveOrgScope(activePattern, "org.records.read", handler))
	f.request(t, "GET", "/actor-records/"+orgA+"/shared-id", "", "", 401)
	actor, err := f.a.GetActor(t.Context(), member.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, org, want string }{
		{name: "tenant A", org: orgA, want: "A"}, {name: "tenant B", org: orgB, want: "B"},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := f.request(t, "GET", "/actor-records/"+test.org+"/shared-id", "", member.SessionToken, 200)
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			value, err := service.Read(t.Context(), actor.ForOrg(test.org), "shared-id")
			if err != nil || value != test.want || body["value"] != test.want {
				t.Fatalf("HTTP/backend mismatch: %s %s %v", body["value"], value, err)
			}
			if received.OrgID != test.org || received.Actor() != actor {
				t.Fatalf("wrong scope: %+v", received)
			}
		})
	}
	if err := f.a.Trusted().Org.SetActiveOrg(t.Context(), api.SetActiveOrgInput{UserID: actor.UserID, SessionID: actor.SessionID, OrgID: orgA}); err != nil {
		t.Fatal(err)
	}
	w := f.request(t, "GET", "/actor-active/shared-id?org_id="+orgB, "", member.SessionToken, 200)
	var activeResult map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &activeResult); err != nil {
		t.Fatal(err)
	}
	if received.OrgID != orgA || activeResult["value"] != "A" {
		t.Fatal("query replaced the session tenant")
	}
	savedScope := received
	for _, test := range []struct {
		name  string
		actor api.OrgPermissionActor
	}{
		{name: "missing user", actor: api.OrgPermissionActor{OrgID: orgA, SessionID: actor.SessionID}},
		{name: "missing session", actor: api.Actor{UserID: actor.UserID}.ForOrg(orgA)},
		{name: "mismatched session", actor: api.Actor{UserID: f.admin.UserID, SessionID: actor.SessionID}.ForOrg(orgA)},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := service.reads
			if _, err := service.Read(t.Context(), test.actor, "shared-id"); !errors.Is(err, domain.ErrOrgForbidden) {
				t.Fatalf("untrusted identity: %v", err)
			}
			if service.reads != before {
				t.Fatal("denied actor reached repository")
			}
		})
	}
	// Changing the role snapshot cannot recover a revoked grant.
	if _, err := f.a.Services().OrgPermissions.SetRolePermissions(t.Context(), api.SetOrgRolePermissionsInput{Actor: f.admin.ForOrg(orgA), RoleID: roleA.ID, ExpectedRevision: roleA.Revision}); err != nil {
		t.Fatal(err)
	}
	savedScope.Role = domain.OrgRoleOwner
	before := service.reads
	if _, err := service.Read(t.Context(), savedScope.PermissionActor(), "shared-id"); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("saved scope bypassed revocation: %v", err)
	}
	f.request(t, "GET", "/actor-records/"+orgA+"/shared-id", "", member.SessionToken, 403)
	f.request(t, "GET", "/actor-active/shared-id", "", member.SessionToken, 403)
	if service.reads != before {
		t.Fatal("revoked grant reached repository")
	}
	// The separate tenant's grant is still valid for this same actor.
	if value, err := service.Read(t.Context(), actor.ForOrg(orgB), "shared-id"); err != nil || value != "B" {
		t.Fatalf("other tenant grant affected: %s %v", value, err)
	}
	if _, err := f.db.ExecContext(t.Context(), "UPDATE sessions SET expires_at = $1 WHERE id = $2", time.Now().Add(-time.Hour), actor.SessionID); err != nil {
		t.Fatal(err)
	}
	before = service.reads
	if _, err := service.Read(t.Context(), actor.ForOrg(orgB), "shared-id"); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("expired actor allowed: %v", err)
	}
	if service.reads != before {
		t.Fatal("expired actor reached repository")
	}
	f.request(t, "GET", "/actor-records/"+orgB+"/shared-id", "", member.SessionToken, 401)
}

func TestAuthorizeOrgDisabledAndBackendFailureReturnNoScope(t *testing.T) {
	if scope, err := (&Auth{}).AuthorizeOrg(t.Context(), api.CheckOrgPermissionInput{}); !errors.Is(err, domain.ErrOrgPermissionsDisabled) || scope != (OrgScope{}) {
		t.Fatalf("disabled: %+v %v", scope, err)
	}
	f := newAppHTTPFixture(t, false, false, WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true}))
	org, err := f.a.Trusted().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Cancelled", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	scope, err := f.a.AuthorizeOrg(ctx, api.CheckOrgPermissionInput{Actor: f.admin.ForOrg(org.ID), PermissionKey: "goauth.org.organization.read"})
	if !errors.Is(err, context.Canceled) || scope != (OrgScope{}) {
		t.Fatalf("backend failure: %+v %v", scope, err)
	}
	if actor, err := f.a.GetActor(ctx, f.token); !errors.Is(err, context.Canceled) || actor != (api.Actor{}) {
		t.Fatalf("authentication failure: %+v %v", actor, err)
	}
}

func TestOrgScopeIdentityCannotCrossJSONBoundary(t *testing.T) {
	scope := OrgScope{OrgID: "org", UserID: "user", SessionID: "session", Role: domain.OrgRoleOwner}
	encoded, err := json.Marshal(scope)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("scope serialized: %s %v", encoded, err)
	}
	var decoded OrgScope
	if err := json.Unmarshal([]byte(`{"orgId":"forged","UserID":"forged","SessionID":"forged","Role":"owner"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != (OrgScope{}) {
		t.Fatalf("JSON populated scope: %+v", decoded)
	}
}

func TestAuthorizeOrgRechecksSessionAssurance(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithOrganizations(OrganizationConfig{Enable: true}), WithOrgPermissions(OrgPermissionsConfig{Enable: true}))
	org, err := f.a.Trusted().Org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.admin.UserID, Name: "Assurance", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := f.a.GetActor(t.Context(), f.token)
	if err != nil {
		t.Fatal(err)
	}
	input := api.CheckOrgPermissionInput{Actor: actor.ForOrg(org.ID), PermissionKey: "goauth.org.organization.read"}
	if _, err := f.a.AuthorizeOrg(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET two_factor_enabled = $1 WHERE id = $2", true, actor.UserID); err != nil {
		t.Fatal(err)
	}
	// Credential validity alone does not assert that the session satisfies the
	// account's newly required second factor. The live action check enforces it.
	if _, err := f.a.GetActor(t.Context(), f.token); err != nil {
		t.Fatal(err)
	}
	if scope, err := f.a.AuthorizeOrg(t.Context(), input); !errors.Is(err, domain.ErrTwoFactorRequired) || scope != (OrgScope{}) {
		t.Fatalf("assurance changed: %+v %v", scope, err)
	}
}
