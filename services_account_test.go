package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func TestServicesDoNotExposeOrWidenTrustedPrimitives(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithOrganizations(OrganizationConfig{Enable: true}), WithProvider(&mockProvider{name: "mock"}), WithAuthentication(AuthenticationConfig{EmailPassword: true, OAuth: true}))
	services := f.a.Services()
	for _, test := range []struct {
		name      string
		value     any
		forbidden []string
	}{
		{name: "auth", value: services.Auth, forbidden: []string{"ChangeName", "Logout", "ValidateSession"}},
		{name: "session", value: services.Session, forbidden: []string{"Create", "RevokeByID", "ValidateWithUser", "ListAll"}},
		{name: "password", value: services.Password, forbidden: []string{"ChangePassword", "RequestSetPassword"}},
		{name: "verification", value: services.Verify, forbidden: []string{"SendVerification", "ResendVerification"}},
		{name: "two factor", value: services.TwoFactor, forbidden: []string{"Challenge", "Enable", "Disable"}},
		{name: "oauth", value: services.OAuth, forbidden: []string{"InitiateLink", "Unlink", "ListConnected"}},
		{name: "org", value: services.Org, forbidden: []string{"CreateOrg", "ClearActiveOrg", "GetMembership", "AdminDeleteOrg"}},
		{name: "invite", value: services.Invite, forbidden: []string{"CreateInvite", "HardDeleteInvite"}},
		{name: "org invite", value: services.OrgInvite, forbidden: []string{"AcceptInvite"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, method := range test.forbidden {
				if _, found := reflect.TypeOf(test.value).MethodByName(method); found {
					t.Fatalf("ordinary %s exposes %s through its concrete method set", test.name, method)
				}
			}
		})
	}
	if _, ok := services.Session.(interface {
		Create(context.Context, api.CreateSessionInput) (*api.SessionResult, error)
	}); ok {
		t.Fatal("session capability widened into credential issuance")
	}
	if _, ok := services.TwoFactor.(interface {
		Challenge(context.Context, string) (*api.ChallengeResult, error)
	}); ok {
		t.Fatal("2FA capability widened into first-factor bypass")
	}
	if _, exists := reflect.TypeFor[Services]().FieldByName("AuditLog"); exists {
		t.Fatal("raw audit repository remains on ordinary Services")
	}
	if _, ok := services.AppPermissions.(interface {
		Initialize(context.Context, api.InitializeAppPermissionsInput) error
	}); ok {
		t.Fatal("ordinary permission capability widened into trusted bootstrap")
	}
	if f.a.Trusted().Session == nil || f.a.Trusted().AuditLog == nil || services.AdminInvite == nil || services.AdminOrg == nil {
		t.Fatal("explicit backend/management capabilities unavailable")
	}
	// Issuance is still available to explicit trusted integrations, and carries
	// no MFA assurance. Its caller must own the prior authentication workflow.
	issued, err := f.a.Trusted().Session.Create(t.Context(), api.CreateSessionInput{UserID: f.admin.UserID})
	if err != nil {
		t.Fatal(err)
	}
	if issued.Session.TwoFactorVerifiedAt != nil {
		t.Fatal("trusted issuance asserted MFA")
	}
}

func TestAccountEveryCapabilityRejectsRevokedActor(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithOrganizations(OrganizationConfig{Enable: true}), WithProvider(&mockProvider{name: "mock"}), WithAuthentication(AuthenticationConfig{EmailPassword: true, OAuth: true}))
	account := f.a.Account(f.admin)
	if err := f.a.Trusted().Session.RevokeByID(t.Context(), f.admin.SessionID); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		call func(context.Context) error
	}{
		{name: "name", call: func(ctx context.Context) error { return account.Profile.ChangeName(ctx, "Should not change") }},
		{name: "delete", call: func(ctx context.Context) error { return account.Profile.DeleteAccount(ctx, "password") }},
		{name: "request delete", call: account.Profile.RequestDeleteAccount},
		{name: "confirm delete", call: func(ctx context.Context) error { return account.Profile.ConfirmDeleteAccount(ctx, "code") }},
		{name: "logout", call: account.Session.Logout},
		{name: "list sessions", call: func(ctx context.Context) error {
			_, _, err := account.Session.List(ctx, api.SessionPageInput{})
			return err
		}},
		{name: "list all sessions", call: func(ctx context.Context) error { _, err := account.Session.ListAll(ctx); return err }},
		{name: "revoke session", call: func(ctx context.Context) error { _, err := account.Session.RevokeByID(ctx, "target"); return err }},
		{name: "revoke many", call: func(ctx context.Context) error {
			_, err := account.Session.RevokeMany(ctx, []string{"target"})
			return err
		}},
		{name: "revoke others", call: account.Session.RevokeOthers},
		{name: "revoke all", call: account.Session.RevokeAll},
		{name: "change password", call: func(ctx context.Context) error {
			return account.Password.ChangePassword(ctx, api.ChangeOwnPasswordInput{})
		}},
		{name: "request password", call: account.Password.RequestSetPassword},
		{name: "confirm password", call: func(ctx context.Context) error {
			return account.Password.ConfirmSetPassword(ctx, api.ConfirmOwnSetPasswordInput{})
		}},
		{name: "resend verification", call: func(ctx context.Context) error { _, err := account.Verify.ResendVerification(ctx); return err }},
		{name: "settings challenge", call: func(ctx context.Context) error {
			_, err := account.TwoFactor.RequestSettingsChallenge(ctx, "enable")
			return err
		}},
		{name: "enable factor", call: func(ctx context.Context) error { return account.TwoFactor.Enable(ctx, api.EnableOwnTwoFactorInput{}) }},
		{name: "disable factor", call: func(ctx context.Context) error { return account.TwoFactor.Disable(ctx, api.DisableOwnTwoFactorInput{}) }},
		{name: "link provider", call: func(ctx context.Context) error { _, err := account.OAuth.InitiateLink(ctx, "mock"); return err }},
		{name: "unlink provider", call: func(ctx context.Context) error { return account.OAuth.Unlink(ctx, "mock") }},
		{name: "list providers", call: func(ctx context.Context) error { _, err := account.OAuth.ListConnected(ctx); return err }},
		{name: "create org", call: func(ctx context.Context) error {
			_, err := account.Org.CreateOrg(ctx, api.CreateOwnOrgInput{})
			return err
		}},
		{name: "list orgs", call: func(ctx context.Context) error {
			_, err := account.Org.ListUserOrgs(ctx, api.ListOwnOrgsInput{})
			return err
		}},
		{name: "count orgs", call: func(ctx context.Context) error {
			_, err := account.Org.CountUserOrgs(ctx, api.ListOwnOrgsInput{})
			return err
		}},
		{name: "leave org", call: func(ctx context.Context) error { return account.Org.LeaveOrg(ctx, "org") }},
		{name: "select org", call: func(ctx context.Context) error { return account.Org.SetActiveOrg(ctx, "org") }},
		{name: "clear org", call: account.Org.ClearActiveOrg},
		{name: "accept org invite", call: func(ctx context.Context) error { return account.OrgInvite.AcceptInvite(ctx, "code") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(t.Context()); !errors.Is(err, domain.ErrForbidden) {
				t.Fatalf("revoked actor was not stopped at account boundary: %v", err)
			}
		})
	}
}

func TestAccountIdentityGuardRejectsStaleOrMismatchedIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*testing.T, appHTTPFixture) api.Actor
		want   error
	}{
		{name: "missing", change: func(*testing.T, appHTTPFixture) api.Actor { return api.Actor{} }, want: domain.ErrForbidden},
		{name: "wrong owner", change: func(t *testing.T, f appHTTPFixture) api.Actor { a := f.admin; a.UserID = "another-user"; return a }, want: domain.ErrForbidden},
		{name: "expired", change: func(t *testing.T, f appHTTPFixture) api.Actor {
			if _, err := f.db.ExecContext(t.Context(), "UPDATE sessions SET expires_at = $1 WHERE id = $2", time.Now().Add(-time.Hour), f.admin.SessionID); err != nil {
				t.Fatal(err)
			}
			return f.admin
		}, want: domain.ErrSessionExpired},
		{name: "banned", change: func(t *testing.T, f appHTTPFixture) api.Actor {
			if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET is_banned = $1 WHERE id = $2", true, f.admin.UserID); err != nil {
				t.Fatal(err)
			}
			return f.admin
		}, want: domain.ErrForbidden},
		{name: "unverified", change: func(t *testing.T, f appHTTPFixture) api.Actor {
			if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET is_verified = $1 WHERE id = $2", false, f.admin.UserID); err != nil {
				t.Fatal(err)
			}
			return f.admin
		}, want: domain.ErrEmailNotVerified},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAppHTTPFixture(t, false, false, WithRegistration(RegistrationConfig{EmailPassword: true, AllowPublic: true, RequireEmailVerification: true}))
			actor := test.change(t, f)
			if err := f.a.Account(actor).Profile.ChangeName(t.Context(), "Forbidden"); !errors.Is(err, test.want) {
				t.Fatalf("error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestAccountSessionOperationsKeepOwnershipAndCurrentSession(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithOrganizations(OrganizationConfig{Enable: true}))
	alice := registerForScopedRoute(t, f.a, "own-alice@example.test")
	bob := registerForScopedRoute(t, f.a, "own-bob@example.test")
	actor, err := f.a.GetActor(t.Context(), alice.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	account := f.a.Account(actor)
	if account.OAuth != nil || f.a.Account(actor).Org == nil {
		t.Fatal("optional account capabilities incorrect")
	}
	other, err := f.a.Trusted().Session.Create(t.Context(), api.CreateSessionInput{UserID: actor.UserID})
	if err != nil {
		t.Fatal(err)
	}
	rows, total, err := account.Session.List(t.Context(), api.SessionPageInput{})
	if err != nil || total != 2 || len(rows) != 2 {
		t.Fatalf("list: %d %d %v", len(rows), total, err)
	}
	for _, row := range rows {
		if row.UserID != actor.UserID {
			t.Fatal("foreign session listed")
		}
	}
	if ok, err := account.Session.RevokeByID(t.Context(), bob.Session.ID); err != nil || ok {
		t.Fatalf("foreign session revoked: %t %v", ok, err)
	}
	if count, err := account.Session.RevokeMany(t.Context(), []string{bob.Session.ID, other.Session.ID}); err != nil || count != 1 {
		t.Fatalf("batch ownership: %d %v", count, err)
	}
	if _, err := f.a.GetActor(t.Context(), bob.SessionToken); err != nil {
		t.Fatal("Bob's session was affected", err)
	}
	if err := account.Session.RevokeOthers(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.GetActor(t.Context(), alice.SessionToken); err != nil {
		t.Fatal("current session revoked", err)
	}
	org, err := account.Org.CreateOrg(t.Context(), api.CreateOwnOrgInput{Name: "Alice org", Slug: "alice-own-org"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := f.a.Trusted().Org.GetMembership(t.Context(), api.GetOrgMembershipInput{OrgID: org.ID, UserID: actor.UserID})
	if err != nil || member == nil || member.Role != domain.OrgRoleOwner {
		t.Fatalf("org owner attribution: %v %v", member, err)
	}
	if err := account.Org.SetActiveOrg(t.Context(), org.ID); err != nil {
		t.Fatal(err)
	}
	if err := account.Org.ClearActiveOrg(t.Context()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := account.Profile.ChangeName(ctx, "Cancelled"); !errors.Is(err, context.Canceled) {
		t.Fatalf("backend failure hidden: %v", err)
	}
	if err := account.Session.RevokeAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := account.Profile.ChangeName(t.Context(), "Old handle"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("retained handle survived revoke-all: %v", err)
	}
}

func TestAccountHTTPMutationCannotSelectAnotherUser(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	alice := registerForScopedRoute(t, f.a, "http-alice@example.test")
	bob := registerForScopedRoute(t, f.a, "http-bob@example.test")
	pattern := "POST /app/account/name"
	f.mux.Handle(pattern, f.a.Protect(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor, ok := middleware.ActorFromContext(r.Context())
		if !ok {
			t.Error("missing authenticated actor")
			w.WriteHeader(500)
			return
		}
		var body struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if err := f.a.Account(actor).Profile.ChangeName(r.Context(), body.Name); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	})))
	f.request(t, "POST", "/app/account/name", `{"name":"Alice renamed","userId":"`+bob.User.ID+`","sessionId":"`+bob.Session.ID+`"}`, alice.SessionToken, 204)
	changed, err := f.users.GetByID(t.Context(), alice.User.ID)
	if err != nil || changed.Name != "Alice renamed" {
		t.Fatalf("Alice not updated: %v %v", changed, err)
	}
	unchanged, err := f.users.GetByID(t.Context(), bob.User.ID)
	if err != nil || unchanged.Name != bob.User.Name {
		t.Fatalf("Bob changed: %v %v", unchanged, err)
	}
}

func TestAccountPasswordAndTwoFactorProofsRemainRequired(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	registered := registerForScopedRoute(t, f.a, "account-proof@example.test")
	actor, err := f.a.GetActor(t.Context(), registered.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	account := f.a.Account(actor)
	if err := account.Password.ChangePassword(t.Context(), api.ChangeOwnPasswordInput{OldPassword: "wrong", NewPassword: "New-Password-123!"}); !errors.Is(err, domain.NewError("wrong_password", "")) {
		t.Fatalf("password proof: %v", err)
	}
	if err := account.TwoFactor.Enable(t.Context(), api.EnableOwnTwoFactorInput{Password: "wrong"}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("MFA settings proof: %v", err)
	}
	other, err := f.a.Trusted().Session.Create(t.Context(), api.CreateSessionInput{UserID: actor.UserID})
	if err != nil {
		t.Fatal(err)
	}
	if err := account.Password.ChangePassword(t.Context(), api.ChangeOwnPasswordInput{OldPassword: validTestPassword(), NewPassword: "New-Password-123!"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.GetActor(t.Context(), registered.SessionToken); err != nil {
		t.Fatal("password change lost initiating session", err)
	}
	if _, err := f.a.GetActor(t.Context(), other.SessionToken); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("other session survived password change: %v", err)
	}
}

func TestAccountVerificationPendingIdentityCanResendAndLogout(t *testing.T) {
	mailer := &testutil.MockMailer{}
	f := newAppHTTPFixture(t, false, false, WithMailer(mailer), WithRegistration(RegistrationConfig{EmailPassword: true, AllowPublic: true, RequireEmailVerification: true}))
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET is_verified = $1 WHERE id = $2", false, f.admin.UserID); err != nil {
		t.Fatal(err)
	}
	account := f.a.Account(f.admin)
	if _, err := account.Verify.ResendVerification(t.Context()); err != nil {
		t.Fatal(err)
	}
	if mailer.SentCount() != 1 {
		t.Fatal("verification was not sent")
	}
	if err := account.Profile.ChangeName(t.Context(), "Restricted"); !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("unverified ordinary access: %v", err)
	}
	if err := account.Session.Logout(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := account.Verify.ResendVerification(t.Context()); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("logged-out actor could resend: %v", err)
	}
}

func TestAccountOAuthLinkUsesTheBoundSession(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithProvider(&mockProvider{name: "mock"}), WithAuthentication(AuthenticationConfig{EmailPassword: true, OAuth: true}))
	alice := registerForScopedRoute(t, f.a, "link-alice@example.test")
	bob := registerForScopedRoute(t, f.a, "link-bob@example.test")
	account := f.a.Account(api.Actor{UserID: alice.User.ID, SessionID: alice.Session.ID})
	flow, err := account.OAuth.InitiateLink(t.Context(), "mock")
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.a.Services().OAuth.Callback(t.Context(), api.OAuthCallbackInput{Provider: "mock", Code: "code", State: flow.State, BrowserState: flow.State, SessionToken: alice.SessionToken})
	if err != nil || !result.IsLink || result.SessionToken != "" {
		t.Fatalf("link outcome: %+v %v", result, err)
	}
	links, err := account.OAuth.ListConnected(t.Context())
	if err != nil || len(links) != 1 || links[0].UserID != alice.User.ID {
		t.Fatalf("Alice provider attribution: %+v %v", links, err)
	}
	bobLinks, err := f.a.Account(api.Actor{UserID: bob.User.ID, SessionID: bob.Session.ID}).OAuth.ListConnected(t.Context())
	if err != nil || len(bobLinks) != 0 {
		t.Fatalf("Bob received Alice's provider: %+v %v", bobLinks, err)
	}
	if err := account.OAuth.Unlink(t.Context(), "mock"); err != nil {
		t.Fatal(err)
	}
	links, err = account.OAuth.ListConnected(t.Context())
	if err != nil || len(links) != 0 {
		t.Fatalf("provider unlink: %+v %v", links, err)
	}
}

func TestAccountCredentialProofs(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithMailer(&testutil.MockMailer{}))
	registered := registerForScopedRoute(t, f.a, "bound-settings@example.test")
	account := f.a.Account(api.Actor{UserID: registered.User.ID, SessionID: registered.Session.ID})
	if _, err := account.Session.RevokeMany(t.Context(), nil); !errors.Is(err, domain.NewError("invalid_input", "")) {
		t.Fatalf("empty revocation batch: %v", err)
	}
	if err := account.Profile.DeleteAccount(t.Context(), "wrong"); !errors.Is(err, domain.NewError("wrong_password", "")) {
		t.Fatalf("deletion password proof: %v", err)
	}
	if err := account.TwoFactor.Enable(t.Context(), api.EnableOwnTwoFactorInput{Password: validTestPassword()}); err != nil {
		t.Fatal(err)
	}
	if err := account.TwoFactor.Disable(t.Context(), api.DisableOwnTwoFactorInput{Password: validTestPassword()}); err != nil {
		t.Fatal(err)
	}
	if err := account.Profile.DeleteAccount(t.Context(), validTestPassword()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.GetActor(t.Context(), registered.SessionToken); !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("deleted account session survived: %v", err)
	}
}

func TestAccountAndHTTPSessionPaginationSharePolicy(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithRateLimitEnabled(false))
	account := f.a.Account(f.admin)
	// More than one page makes a cap meaningful; a one-session fixture would
	// pass even if the Go operation accidentally fetched an unbounded result.
	for range 104 {
		if _, err := f.a.Trusted().Session.Create(t.Context(), api.CreateSessionInput{
			UserID: f.admin.UserID,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name                             string
		input                            api.SessionPageInput
		wantLimit, wantOffset, wantCount int
	}{
		{name: "default", wantLimit: 20, wantCount: 20},
		{name: "negative limit", input: api.SessionPageInput{Limit: -1}, wantLimit: 20, wantCount: 20},
		{name: "negative offset", input: api.SessionPageInput{Offset: -1, Limit: 5}, wantLimit: 5, wantCount: 5},
		{
			name:       "normal page",
			input:      api.SessionPageInput{Offset: 100, Limit: 10},
			wantLimit:  10,
			wantOffset: 100,
			wantCount:  5,
		},
		{name: "maximum", input: api.SessionPageInput{Limit: 100}, wantLimit: 100, wantCount: 100},
		{name: "above maximum", input: api.SessionPageInput{Limit: 101}, wantLimit: 100, wantCount: 100},
	} {
		t.Run(test.name, func(t *testing.T) {
			rows, total, err := account.Session.List(t.Context(), test.input)
			if err != nil || total != 105 || len(rows) != test.wantCount {
				t.Fatalf("Go page: count=%d total=%d error=%v", len(rows), total, err)
			}
			path := "/auth/sessions?offset=" + strconv.Itoa(test.input.Offset) + "&limit=" + strconv.Itoa(test.input.Limit)
			response := f.request(t, "GET", path, "", f.token, http.StatusOK)
			var page struct {
				Sessions []domain.Session `json:"sessions"`
				Total    int              `json:"total"`
				Offset   int              `json:"offset"`
				Limit    int              `json:"limit"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			if page.Total != total || len(page.Sessions) != len(rows) ||
				page.Limit != test.wantLimit || page.Offset != test.wantOffset {
				t.Fatalf(
					"HTTP/Go pagination differs: count=%d total=%d limit=%d offset=%d",
					len(page.Sessions), page.Total, page.Limit, page.Offset,
				)
			}
		})
	}
	rows, _, err := f.a.Trusted().Session.List(t.Context(), api.ListSessionsInput{
		UserID: f.admin.UserID, Limit: 101,
	})
	if err != nil || len(rows) != 100 {
		t.Fatalf("service-level pagination not enforced: %d %v", len(rows), err)
	}
}

func TestAccountAndHTTPBatchRevocationShareValidation(t *testing.T) {
	f := newAppHTTPFixture(t, false, false)
	for _, test := range []struct {
		name       string
		sessionIDs []string
	}{
		{name: "empty"},
		{name: "too many", sessionIDs: make([]string, 101)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := f.a.Account(f.admin).Session.RevokeMany(t.Context(), test.sessionIDs)
			var failure *domain.AuthError
			if !errors.As(err, &failure) || failure.Code != "invalid_input" {
				t.Fatalf("Go validation: %v", err)
			}
			body, err := json.Marshal(map[string]any{"sessionIds": test.sessionIDs})
			if err != nil {
				t.Fatal(err)
			}
			response := f.request(t, "POST", "/auth/sessions/revoke", string(body), f.token, 400)
			var httpFailure domain.AuthError
			if err := json.Unmarshal(response.Body.Bytes(), &httpFailure); err != nil {
				t.Fatal(err)
			}
			if httpFailure.Code != failure.Code || httpFailure.Message != failure.Message {
				t.Fatalf("HTTP/Go errors differ: %+v %+v", httpFailure, failure)
			}
		})
	}
}
