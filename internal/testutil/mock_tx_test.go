package testutil

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

func TestMockTxManagerCommitsAndRollsBackRepositories(t *testing.T) {
	for _, outcome := range []string{"commit", "error", "cancel", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			users, tokens, sessions := NewMockUserRepo(), NewMockTokenRepo(), NewMockSessionRepo()
			invites, orgs, orgInvites := NewMockInviteRepo(), NewMockOrgRepo(), NewMockOrgInviteRepo()
			providers := NewMockProviderAccountRepo()
			userID := "user"
			now := time.Now().UTC()
			for _, err := range []error{
				users.Create(t.Context(), &domain.User{ID: userID, Email: "user@example.com"}),
				tokens.Create(t.Context(), &domain.VerificationToken{ID: "token", TokenHash: "code", UserID: &userID, ExpiresAt: now.Add(time.Hour)}),
				sessions.Create(t.Context(), &domain.Session{ID: "session", UserID: userID, TokenHash: "access", RefreshTokenHash: "refresh"}),
				invites.Create(t.Context(), &domain.Invite{ID: "invite", Email: "invite@example.com", Code: "invite-code", Status: domain.InvitePending, ExpiresAt: now.Add(time.Hour)}),
				orgs.AddMember(t.Context(), &domain.OrgMember{OrgID: "org", UserID: userID, Role: domain.OrgRoleMember}),
				orgInvites.Create(t.Context(), &domain.OrgInvite{ID: "org-invite", CodeHash: "org-code", ExpiresAt: now.Add(time.Hour)}),
				providers.Create(t.Context(), &domain.ProviderAccount{ID: "provider", UserID: userID, Provider: "google", ProviderUserID: "remote"}),
			} {
				if err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			sentinel := errors.New("transaction must roll back")
			var recovered any
			var err error
			func() {
				defer func() { recovered = recover() }()
				err = (&MockTxManager{}).WithTx(ctx, func(txCtx context.Context) error {
					if ok, err := users.VerifyEmailIfMatches(txCtx, userID, "user@example.com", now); err != nil || !ok {
						t.Fatalf("verify = %v, %v", ok, err)
					}
					for _, err := range []error{
						tokens.MarkUsed(txCtx, "token"),
						sessions.DeleteAllForUser(txCtx, userID),
						providers.Delete(txCtx, userID, "google"),
						users.Create(txCtx, &domain.User{ID: "new-user", Email: "new@example.com"}),
					} {
						if err != nil {
							t.Fatal(err)
						}
					}
					for _, claim := range []func() (bool, error){
						func() (bool, error) { return invites.ClaimInvite(txCtx, "invite-code", now) },
						func() (bool, error) { return orgInvites.ClaimInvite(txCtx, "org-invite", "org-code") },
						func() (bool, error) {
							return orgs.UpdateMemberRole(txCtx, "org", userID, domain.OrgRoleMember, domain.OrgRoleAdmin)
						},
					} {
						if ok, err := claim(); err != nil || !ok {
							t.Fatalf("guarded mutation = %v, %v", ok, err)
						}
					}
					switch outcome {
					case "error":
						return sentinel
					case "cancel":
						cancel()
					case "panic":
						panic(sentinel)
					}
					return nil
				})
			}()
			if outcome == "error" && !errors.Is(err, sentinel) ||
				outcome == "cancel" && !errors.Is(err, context.Canceled) ||
				outcome == "panic" && recovered != sentinel ||
				outcome == "commit" && (err != nil || recovered != nil) {
				t.Fatalf("outcome=%s: err=%v, panic=%v", outcome, err, recovered)
			}
			committed := outcome == "commit"
			user, err := users.GetByEmail(t.Context(), "user@example.com")
			if err != nil || user.IsVerified != committed {
				t.Fatalf("user verification survived rollback or failed commit: %+v, %v", user, err)
			}
			newUser, err := users.GetByID(t.Context(), "new-user")
			if err != nil || (newUser != nil) != committed {
				t.Fatalf("created row survived rollback or failed commit: %+v, %v", newUser, err)
			}
			token, err := tokens.GetByHash(t.Context(), "code")
			if err != nil || (token.UsedAt != nil) != committed {
				t.Fatalf("token claim survived rollback or failed commit: %+v, %v", token, err)
			}
			invite, err := invites.GetByCode(t.Context(), "invite-code")
			if err != nil || (invite.AcceptedAt != nil) != committed {
				t.Fatalf("invite claim survived rollback or failed commit: %+v, %v", invite, err)
			}
			member, err := orgs.GetMembership(t.Context(), "org", userID)
			if err != nil || (member.Role == domain.OrgRoleAdmin) != committed {
				t.Fatalf("membership mutation survived rollback or failed commit: %+v, %v", member, err)
			}
			session, err := sessions.GetByRefreshHash(t.Context(), "refresh")
			if err != nil || (session == nil) != committed {
				t.Fatalf("session deletion survived rollback or failed commit: %+v, %v", session, err)
			}
			orgInvite, err := orgInvites.GetByCodeHash(t.Context(), "org-code")
			if err != nil || (orgInvite == nil) != committed {
				t.Fatalf("org invite deletion survived rollback or failed commit: %+v, %v", orgInvite, err)
			}
			provider, err := providers.GetByProvider(t.Context(), "google", "remote")
			if err != nil || (provider == nil) != committed {
				t.Fatalf("provider deletion survived rollback or failed commit: %+v, %v", provider, err)
			}
		})
	}
}

func TestMockTxManagerNestedCallsRollBackWithParent(t *testing.T) {
	repo := NewMockUserRepo()
	tx := &MockTxManager{}
	want := errors.New("parent failure")
	err := tx.WithTx(t.Context(), func(ctx context.Context) error {
		if err := (&MockTxManager{}).WithTx(ctx, func(ctx context.Context) error {
			return repo.Create(ctx, &domain.User{ID: "user", Email: "user@example.com"})
		}); err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	if user, err := repo.GetByID(t.Context(), "user"); err != nil || user != nil {
		t.Fatal("nested transaction committed independently of its parent")
	}
}

func TestMockTxManagerRejectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := (&MockTxManager{}).WithTx(ctx, func(context.Context) error {
		t.Fatal("callback ran after cancellation")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestMockTxManagerRollsBackSetPasswordClaims(t *testing.T) {
	repo := NewMockUserRepo()
	if err := repo.Create(t.Context(), &domain.User{ID: "user", Email: "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	tx := &MockTxManager{}
	want := errors.New("later write failed")
	err := tx.WithTx(t.Context(), func(ctx context.Context) error {
		if ok, err := repo.SetPasswordAndVerify(ctx, "user", "hash", nil, "code"); err != nil || !ok {
			t.Fatalf("set password = %v, %v", ok, err)
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	if user, err := repo.GetByID(t.Context(), "user"); err != nil || user.HasPassword() || user.IsVerified {
		t.Fatalf("credential survived rollback: %+v, %v", user, err)
	}
	if ok, err := repo.SetPasswordAndVerify(t.Context(), "user", "hash", nil, "code"); err != nil || !ok {
		t.Fatalf("rolled-back token could not be claimed again: %v, %v", ok, err)
	}
}

func TestMockTxManagerRollsBackNestedMetadata(t *testing.T) {
	repo := NewMockOrgRepo()
	if err := repo.Create(t.Context(), &domain.Organization{ID: "org", Slug: "org", Metadata: map[string]any{
		"nested": map[string]any{"value": "original"},
	}}); err != nil {
		t.Fatal(err)
	}
	want := errors.New("later write failed")
	err := (&MockTxManager{}).WithTx(t.Context(), func(ctx context.Context) error {
		org, err := repo.GetByID(ctx, "org")
		if err != nil {
			return err
		}
		org.Metadata["nested"].(map[string]any)["value"] = "changed"
		return want
	})
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	org, err := repo.GetBySlug(t.Context(), "org")
	if err != nil || org.Metadata["nested"].(map[string]any)["value"] != "original" {
		t.Fatal("rollback shared mutable nested metadata with the changed row")
	}
}

func TestMockAdminGuardRollsBackUserAndSessions(t *testing.T) {
	users, sessions := NewMockUserRepo(), NewMockSessionRepo()
	if err := users.Create(t.Context(), &domain.User{ID: "user", Email: "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Create(t.Context(), &domain.Session{ID: "session", UserID: "user", TokenHash: "access"}); err != nil {
		t.Fatal(err)
	}
	want := errors.New("later guarded write failed")
	err := users.WithAdminGuard(t.Context(), func(ctx context.Context) error {
		if ok, err := users.BanWithAdminGuard(ctx, "user", true, nil, time.Now().UTC()); err != nil || !ok {
			t.Fatalf("ban = %v, %v", ok, err)
		}
		if err := sessions.DeleteAllForUser(ctx, "user"); err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	if user, err := users.GetByID(t.Context(), "user"); err != nil || user.IsBanned {
		t.Fatal("failed guard left the user banned")
	}
	if session, err := sessions.GetByTokenHash(t.Context(), "access"); err != nil || session == nil {
		t.Fatal("failed guard deleted the session")
	}
}
