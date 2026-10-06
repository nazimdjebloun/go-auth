package service

import (
	"context"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type identityLookupGuard struct {
	*testutil.MockProviderAccountRepo
	t *testing.T
}

func (r *identityLookupGuard) GetByProvider(context.Context, string, string) (*domain.ProviderAccount, error) {
	r.t.Fatal("invalid profile reached the identity lookup")
	return nil, nil
}

func TestOAuthCallbackRejectsInvalidIdentityBeforeLookup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile *port.OAuthProfile
	}{
		{"nil profile", nil},
		{"missing subject", oauthTestProfile("test", "", "user@example.com")},
		{"blank subject", oauthTestProfile("test", " \t", "user@example.com")},
		{"wrong provider", oauthTestProfile("other", "subject", "user@example.com")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := testutil.NewMockUserRepo()
			tokens := testutil.NewMockTokenRepo()
			repo := &identityLookupGuard{MockProviderAccountRepo: testutil.NewMockProviderAccountRepo(), t: t}
			svc, _ := newTestOAuthService(map[string]port.OAuthProvider{
				"test": &stubOAuthProvider{name: "test", profile: tc.profile},
			}, repo, users, tokens)
			seedOAuthState(t, tokens, "state", "raw-state")
			result, err := svc.Callback(context.Background(), api.OAuthCallbackInput{
				Provider:     "test",
				Code:         "code",
				State:        "raw-state",
				BrowserState: "raw-state",
				SessionToken: "",
				IP:           "",
				UserAgent:    "",
			})
			if authErrCode(err) != "provider_error" || result != nil {
				t.Fatalf("invalid identity accepted: result=%+v err=%v", result, err)
			}
		})
	}
}

func TestOAuthCallbackRejectsInvalidRegistrationEmail(t *testing.T) {
	for _, email := range []string{"", "not-an-email"} {
		t.Run(email, func(t *testing.T) {
			users := testutil.NewMockUserRepo()
			tokens := testutil.NewMockTokenRepo()
			svc, _ := newTestOAuthService(map[string]port.OAuthProvider{
				"test": &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "subject", email)},
			}, testutil.NewMockProviderAccountRepo(), users, tokens)
			seedOAuthState(t, tokens, "state", "raw-state")
			result, err := svc.Callback(context.Background(), api.OAuthCallbackInput{
				Provider:     "test",
				Code:         "code",
				State:        "raw-state",
				BrowserState: "raw-state",
				SessionToken: "",
				IP:           "",
				UserAgent:    "",
			})
			if authErrCode(err) != "provider_error" || result != nil {
				t.Fatalf("invalid registration email accepted: result=%+v err=%v", result, err)
			}
			user, _ := users.GetByEmail(context.Background(), email)
			if user != nil {
				t.Fatal("invalid profile created a user")
			}
		})
	}
}

func TestOAuthCallbackLinkedIdentityDoesNotRequireCurrentEmail(t *testing.T) {
	ctx := context.Background()
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	repo := testutil.NewMockProviderAccountRepo()
	user := &domain.User{ID: "user", Email: "user@example.com", IsVerified: true}
	if err := users.Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, &domain.ProviderAccount{
		ID: "account", UserID: user.ID, Provider: "test", ProviderUserID: "subject",
	}); err != nil {
		t.Fatal(err)
	}
	svc, _ := newTestOAuthService(map[string]port.OAuthProvider{
		"test": &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "subject", "")},
	}, repo, users, tokens)
	seedOAuthState(t, tokens, "state", "raw-state")
	result, err := svc.Callback(ctx, api.OAuthCallbackInput{
		Provider:     "test",
		Code:         "code",
		State:        "raw-state",
		BrowserState: "raw-state",
		SessionToken: "",
		IP:           "",
		UserAgent:    "",
	})
	if err != nil || result == nil || result.SessionToken == "" {
		t.Fatalf("linked identity without current email rejected: result=%+v err=%v", result, err)
	}
}
