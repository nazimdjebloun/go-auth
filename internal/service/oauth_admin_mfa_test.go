package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestOAuthAdminLoginRequiresSecondFactorBeforeSession(t *testing.T) {
	for _, optOut := range []bool{false, true} {
		for _, userEnabled := range []bool{false, true} {
			t.Run(map[bool]string{false: "required", true: "opt-out"}[optOut]+map[bool]string{false: "/unflagged", true: "/user-enabled"}[userEnabled], func(t *testing.T) {
				ctx := context.Background()
				users := testutil.NewMockUserRepo()
				tokens := testutil.NewMockTokenRepo()
				providers := testutil.NewMockProviderAccountRepo()
				user := &domain.User{ID: "admin", Email: "admin@test.com", Role: domain.RoleAdmin, IsVerified: true, TwoFactorEnabled: userEnabled}
				if err := users.Create(ctx, user); err != nil {
					t.Fatal(err)
				}
				if err := providers.Create(ctx, &domain.ProviderAccount{ID: "identity", UserID: user.ID, Provider: "test", ProviderUserID: "subject"}); err != nil {
					t.Fatal(err)
				}
				oauth, sessions := newTestOAuthService(map[string]port.OAuthProvider{
					"test": &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "subject", user.Email)},
				}, providers, users, tokens)
				cfg := defaultTestConfig()
				cfg.DisableAdminTwoFactor = optOut
				cfg.TwoFactorCodeTTL = 5 * time.Minute
				cfg.TwoFactorBindingKey = []byte("test-binding-key-32-bytes-long!!")
				mailer := &testutil.MockMailer{}
				twoFactor := NewTwoFactorService(users, sessions, tokens, &testutil.MockHasher{}, mailer, nil, cfg, oauth.sessionSvc)
				oauth.config.DisableAdminTwoFactor = optOut
				oauth.AttachTwoFactor(twoFactor)
				seedOAuthState(t, tokens, "state", "raw-state")
				result, err := oauth.Callback(ctx, "test", "code", "raw-state", "raw-state", "", "", "")
				if err != nil {
					t.Fatal(err)
				}
				if optOut && !userEnabled {
					if result.SessionToken == "" || result.RequiresTwoFactor {
						t.Fatalf("opt-out callback did not return a session: %+v", result)
					}
					return
				}
				if !result.RequiresTwoFactor || result.TwoFactorChallenge == "" || result.BindingToken() == "" || result.SessionToken != "" {
					t.Fatalf("admin callback bypassed MFA: %+v", result)
				}
				live, err := sessions.ListAllByUserID(ctx, user.ID)
				if err != nil || len(live) != 0 {
					t.Fatalf("callback issued a session before verification: %v, %v", live, err)
				}
				verified, err := twoFactor.Verify(ctx, result.TwoFactorChallenge, result.BindingToken(), testutil.GetLastVerificationCode(mailer), "", "")
				if err != nil || verified.Session.TwoFactorVerifiedAt == nil {
					t.Fatalf("OAuth challenge verification did not create assurance: %+v, %v", verified, err)
				}
			})
		}
	}
}
