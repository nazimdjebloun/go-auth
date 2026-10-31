package service

import (
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestOAuthCallback_PreservesSessionContext(t *testing.T) {
	for _, scope := range []sessioncontext.Scope{sessioncontext.App, sessioncontext.Admin} {
		t.Run(string(scope), func(t *testing.T) {
			ctx := t.Context()
			users := testutil.NewMockUserRepo()
			tokens := testutil.NewMockTokenRepo()
			svc, _ := newTestOAuthService(map[string]port.OAuthProvider{
				"test": &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "subject", "oauth@example.com")},
			}, testutil.NewMockProviderAccountRepo(), users, tokens)
			// Establish an existing provider identity through the ordinary signup flow.
			seedOAuthState(t, tokens, "signup", "signup-state")
			if _, err := svc.Callback(ctx, api.OAuthCallbackInput{Provider: "test", State: "signup-state", BrowserState: "signup-state"}); err != nil {
				t.Fatal(err)
			}
			user, err := users.GetByEmail(ctx, "oauth@example.com")
			if err != nil {
				t.Fatal(err)
			}
			user.Role = domain.RoleAdmin
			if err := users.Update(ctx, user); err != nil {
				t.Fatal(err)
			}
			svc.config.DisableAdminTwoFactor = true
			initiation, err := svc.Initiate(sessioncontext.With(ctx, scope), "test")
			if err != nil {
				t.Fatal(err)
			}
			if sessioncontext.Of(initiation.State) != scope {
				t.Fatal("state lost initiating context")
			}
			// Editing the context label must fail even if both browser copies match.
			tampered := "ga-admin." + initiation.State
			if scope == sessioncontext.Admin {
				tampered = strings.TrimPrefix(initiation.State, "ga-admin.")
			}
			if _, err := svc.Callback(ctx, api.OAuthCallbackInput{Provider: "test", State: tampered, BrowserState: tampered}); authErrCode(err) != "invalid_state" {
				t.Fatalf("modified state label accepted: %v", err)
			}
			// Provider callbacks have no selector header; verified state restores it.
			result, err := svc.Callback(ctx, api.OAuthCallbackInput{Provider: "test", State: initiation.State, BrowserState: initiation.State})
			if err != nil {
				t.Fatal(err)
			}
			if result.SessionToken == "" || sessioncontext.Of(result.SessionToken) != scope || sessioncontext.Of(result.RefreshToken) != scope {
				t.Fatal("callback issued credentials in the wrong context")
			}
			other := sessioncontext.App
			if scope == sessioncontext.App {
				other = sessioncontext.Admin
			}
			if _, err := svc.sessionSvc.Validate(sessioncontext.With(ctx, other), result.SessionToken); err == nil {
				t.Fatal("credential accepted in the other context")
			}
			if _, err := svc.Callback(ctx, api.OAuthCallbackInput{Provider: "test", State: initiation.State, BrowserState: initiation.State}); authErrCode(err) != "state_used" {
				t.Fatalf("state replay accepted: %v", err)
			}
		})
	}
}
