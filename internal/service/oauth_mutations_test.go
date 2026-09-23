package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type failingEmailVerifier struct{ port.UserRepository }

func (r failingEmailVerifier) VerifyEmailIfMatches(context.Context, string, string, time.Time) (bool, error) {
	return false, errors.New("injected verification failure")
}

func TestOAuthCallback_VerificationMutation(t *testing.T) {
	for _, scenario := range []string{"matching email", "different email", "write failure"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			users := testutil.NewMockUserRepo()
			tokens := testutil.NewMockTokenRepo()
			providers := testutil.NewMockProviderAccountRepo()
			user := &domain.User{ID: "linked-user", Email: "local@example.com", Name: "Local name", Role: domain.RoleUser}
			if err := users.Create(ctx, user); err != nil {
				t.Fatal(err)
			}
			if err := providers.Create(ctx, &domain.ProviderAccount{ID: "link", UserID: user.ID, Provider: "test", ProviderUserID: "provider-user"}); err != nil {
				t.Fatal(err)
			}
			email := user.Email
			if scenario == "different email" {
				email = "other@example.com"
			}
			svc, sessions := newTestOAuthService(map[string]port.OAuthProvider{"test": &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "provider-user", email)}}, providers, users, tokens)
			if scenario == "write failure" {
				svc.userRepo = failingEmailVerifier{UserRepository: users}
			}
			seedOAuthState(t, tokens, "state", "raw-state")
			result, err := svc.Callback(ctx, "test", "code", "raw-state", "raw-state", "", "127.0.0.1", "test")
			if scenario == "write failure" {
				if result != nil || !errors.Is(err, domain.ErrInternal) {
					t.Fatalf("result=%v err=%v", result, err)
				}
				stored, _, err := sessions.ListByUserID(ctx, user.ID, 0, 10)
				if err != nil {
					t.Fatal(err)
				}
				if len(stored) != 0 {
					t.Fatal("created session after failed verification write")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			stored, err := users.GetByID(ctx, user.ID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.IsVerified != (scenario == "matching email") || stored.Email != "local@example.com" || stored.Name != "Local name" {
				t.Fatalf("unexpected persisted identity: %+v", stored)
			}
		})
	}
}
