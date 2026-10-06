package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
)

func TestOAuthUnlinkCountsMethodsRemainingAfterProviderDeletion(t *testing.T) {
	for _, name := range []string{"passwordless same provider", "another provider remains", "password remains"} {
		t.Run(name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			ctx := context.Background()
			if name != "password remains" {
				if _, err := f.db.ExecContext(context.Background(), "UPDATE users SET password_hash = NULL WHERE id = $1", f.userID); err != nil {
					t.Fatal(err)
				}
			}
			repo := sqlstore.NewProviderAccountRepository(f.db)
			now := time.Now().UTC()
			providers := []string{"google", "google"}
			if name == "another provider remains" {
				providers = append(providers, "github")
			}
			for i, provider := range providers {
				id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+60)
				if err := repo.Create(ctx, &domain.ProviderAccount{
					ID: id, UserID: f.userID, Provider: provider, ProviderUserID: id, CreatedAt: now, UpdatedAt: now,
				}); err != nil {
					t.Fatal(err)
				}
			}
			svc := NewOAuthService(nil, repo, f.users, f.tokens, f.hasher, nil, nil, nil, f.db, OAuthServiceConfig{})
			err := svc.Unlink(ctx, api.OAuthUnlinkInput{
				UserID:   f.userID,
				Provider: "google",
			})
			accounts, lookupErr := repo.ListByUserID(ctx, f.userID)
			if lookupErr != nil {
				t.Fatal(lookupErr)
			}
			if name == "passwordless same provider" {
				if !errors.Is(err, domain.ErrCannotUnlinkLastProvider) || len(accounts) != 2 {
					t.Fatalf("last method deleted: accounts=%+v err=%v", accounts, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				for _, account := range accounts {
					if account.Provider == "google" {
						t.Fatal("unlink did not remove all selected identities")
					}
				}
				want := 0
				if name == "another provider remains" {
					want = 1
				}
				if len(accounts) != want {
					t.Fatalf("remaining identities=%d want=%d", len(accounts), want)
				}
			}
		})
	}
}
