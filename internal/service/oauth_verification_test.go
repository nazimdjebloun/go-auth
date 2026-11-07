package service

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestOAuthVerificationDeliveryPreservesAccountAndProvider(t *testing.T) {
	for _, failure := range []string{"none", "send", "render"} {
		t.Run(failure, func(t *testing.T) {
			users := testutil.NewMockUserRepo()
			tokens := testutil.NewMockTokenRepo()
			providers := testutil.NewMockProviderAccountRepo()
			profile := oauthTestProfile("test", "provider-user", "oauth-pending@example.test")
			profile.EmailVerified = false
			svc, sessions := newTestOAuthService(map[string]port.OAuthProvider{
				"test": &stubOAuthProvider{name: "test", profile: profile},
			}, providers, users, tokens)
			svc.config.RequireEmailVerification = true
			mailer := &testutil.MockMailer{}
			if failure == "send" {
				mailer.SendFn = func(context.Context, string, string, string, string) error {
					return errors.New("delivery unavailable")
				}
			}
			svc.verifySvc.mailer = mailer
			templates := svc.verifySvc.templates
			if failure == "render" {
				svc.verifySvc.templates = &deliveryTestTemplates{fail: true}
			}
			var userID string
			for attempt := range 2 {
				state := fmt.Sprintf("verification-state-%d", attempt)
				seedOAuthState(t, tokens, state, state)
				result, err := svc.Callback(t.Context(), api.OAuthCallbackInput{
					Provider: "test", Code: "code", State: state, BrowserState: state,
				})
				if err != nil || result == nil {
					t.Fatalf("established OAuth identity reported failure: result=%v err=%v", result, err)
				}
				want := api.VerificationDeliveryFailed
				if failure == "none" {
					want = api.VerificationDeliverySent
					if attempt != 0 {
						want = api.VerificationDeliveryNotSent
					}
				}
				if !result.RequiresVerification || result.VerificationDelivery != want || result.IsNewUser != (attempt == 0) {
					t.Fatalf("OAuth outcome: pending=%v delivery=%q new=%v", result.RequiresVerification, result.VerificationDelivery, result.IsNewUser)
				}
				if result.SessionToken != "" || result.RefreshToken != "" || result.SessionID != "" {
					t.Fatal("pending OAuth account received credentials")
				}
				user, err := users.GetByEmail(t.Context(), profile.Email)
				if err != nil || user == nil || user.IsVerified {
					t.Fatalf("pending OAuth user missing: %v", err)
				}
				if userID != "" && userID != user.ID {
					t.Fatal("repeat OAuth callback created another account")
				}
				userID = user.ID
				links, err := providers.ListByUserID(t.Context(), userID)
				if err != nil || len(links) != 1 {
					t.Fatalf("provider link lost: count=%d err=%v", len(links), err)
				}
				active, err := sessions.ListAllByUserID(t.Context(), userID)
				if err != nil || len(active) != 0 {
					t.Fatalf("pending OAuth sessions=%d err=%v", len(active), err)
				}
			}
			// Once delivery recovers, resend and verification resume the same
			// identity rather than requiring another signup or provider link.
			mailer.SendFn = nil
			svc.verifySvc.templates = templates
			if _, err := svc.verifySvc.ResendVerification(t.Context(), userID); err != nil {
				t.Fatal(err)
			}
			code := testutil.GetLastVerificationCode(mailer)
			if _, err := svc.verifySvc.VerifyEmail(t.Context(), code); err != nil {
				t.Fatal(err)
			}
			seedOAuthState(t, tokens, "verified-state", "verified-state")
			result, err := svc.Callback(t.Context(), api.OAuthCallbackInput{
				Provider: "test", Code: "code", State: "verified-state", BrowserState: "verified-state",
			})
			if err != nil || result == nil || result.IsNewUser || result.SessionToken == "" || result.VerificationDelivery != "" {
				t.Fatalf("verified identity did not complete login: result=%v err=%v", result, err)
			}
		})
	}
}
