package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type linkExchangeBarrier struct {
	stubOAuthProvider
	entered chan struct{}
	release chan struct{}
}

func (p *linkExchangeBarrier) Exchange(ctx context.Context, _, _ string) (*port.OAuthProfile, error) {
	close(p.entered)
	select {
	case <-p.release:
		return p.profile, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestOAuthLinkRechecksAuthorityAfterExchange(t *testing.T) {
	for _, change := range []string{"none", "revoke", "reset", "email", "ban", "unverify", "expire state", "delete state", "expire session", "rotate session"} {
		t.Run(change, func(t *testing.T) {
			f := newEmailFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			provider := &linkExchangeBarrier{
				stubOAuthProvider: stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "new-subject", "provider@example.com")},
				entered:           make(chan struct{}), release: make(chan struct{}),
			}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(provider.release) }) }
			gen := &testutil.MockTokenGen{Length: 32}
			sessions := NewSessionService(f.db, f.sessions, gen, DefaultSessionConfig())
			origin, err := sessions.Create(ctx, api.CreateSessionInput{UserID: f.userID})
			if err != nil {
				t.Fatal(err)
			}
			accounts := sqlstore.NewProviderAccountRepository(f.db)
			svc := NewOAuthService(map[string]port.OAuthProvider{"test": provider}, accounts, f.users, f.tokens,
				f.hasher, gen, sessions, nil, f.db, OAuthServiceConfig{OAuth: true, RequireEmailVerification: true})
			flow, err := svc.InitiateLink(ctx, api.OAuthLinkInput{Provider: "test", UserID: f.userID, SessionTokenHash: origin.Session.TokenHash})
			if err != nil {
				t.Fatal(err)
			}
			state, err := f.tokens.GetByHash(ctx, hashToken(flow.State))
			if err != nil || state == nil {
				t.Fatalf("state=%+v err=%v", state, err)
			}
			type outcome struct {
				result *api.OAuthCallbackResult
				err    error
			}
			done := make(chan outcome, 1)
			finished := false
			defer func() {
				release()
				cancel()
				if !finished {
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Error("callback did not terminate")
					}
				}
			}()
			go func() {
				result, err := svc.Callback(ctx, api.OAuthCallbackInput{Provider: "test", Code: "dummy-code",
					State: flow.State, BrowserState: flow.State, SessionToken: origin.SessionToken})
				done <- outcome{result, err}
			}()
			select {
			case <-provider.entered:
			case <-ctx.Done():
				t.Fatal("callback did not reach exchange")
			}
			switch change {
			case "revoke":
				_, err = sessions.RevokeByIDForUser(ctx, api.RevokeSessionForUserInput{SessionID: origin.Session.ID, UserID: f.userID})
			case "reset":
				err = f.passwordService(f.hasher, f.sessions).ResetPassword(ctx, api.ResetPasswordInput{Code: f.code, NewPassword: "NewPass2!"})
			case "email":
				request := f.request(t)
				err = f.svc.ConfirmEmailChange(ctx, f.proof(t, request))
			case "ban":
				_, err = f.db.ExecContext(ctx, "UPDATE users SET is_banned = $1 WHERE id = $2", true, f.userID)
			case "unverify":
				_, err = f.db.ExecContext(ctx, "UPDATE users SET is_verified = $1 WHERE id = $2", false, f.userID)
			case "expire state":
				_, err = f.db.ExecContext(ctx, "UPDATE verification_tokens SET expires_at = $1 WHERE id = $2", time.Now().UTC().Add(-time.Minute), state.ID)
			case "delete state":
				_, err = f.db.ExecContext(ctx, "DELETE FROM verification_tokens WHERE id = $1", state.ID)
			case "expire session":
				_, err = f.db.ExecContext(ctx, "UPDATE sessions SET expires_at = $1 WHERE id = $2", time.Now().UTC().Add(-time.Minute), origin.Session.ID)
			case "rotate session":
				_, err = sessions.RefreshSession(ctx, origin.RefreshToken)
			}
			if err != nil {
				t.Fatal(err)
			}
			release()
			var got outcome
			select {
			case got = <-done:
				finished = true
			case <-ctx.Done():
				t.Fatal("callback did not finish")
			}
			account, err := accounts.GetByProvider(ctx, "test", "new-subject")
			if err != nil {
				t.Fatal(err)
			}
			if change == "none" {
				if got.err != nil || got.result == nil || !got.result.IsLink || account == nil {
					t.Fatalf("valid link: result=%+v err=%v account=%+v", got.result, got.err, account)
				}
			} else if got.err == nil || account != nil {
				t.Fatalf("stale authority saved link: result=%+v err=%v account=%+v", got.result, got.err, account)
			} else {
				want := "unauthorized"
				switch change {
				case "ban":
					want = "user_banned"
				case "unverify":
					want = "email_not_verified"
				case "expire state":
					want = "state_expired"
				case "delete state":
					want = "invalid_state"
				}
				if authErrCode(got.err) != want {
					t.Fatalf("error=%v, want %s", got.err, want)
				}
			}
		})
	}
}

type insertThenFailProvider struct{ port.ProviderAccountRepository }

func (r insertThenFailProvider) Create(ctx context.Context, account *domain.ProviderAccount) error {
	if err := r.ProviderAccountRepository.Create(ctx, account); err != nil {
		return err
	}
	return errors.New("injected post-insert failure")
}

func TestOAuthLinkInsertFailureRollsBack(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	ctx := t.Context()
	gen := &testutil.MockTokenGen{Length: 32}
	sessions := NewSessionService(f.db, f.sessions, gen, DefaultSessionConfig())
	origin, err := sessions.Create(ctx, api.CreateSessionInput{UserID: f.userID})
	if err != nil {
		t.Fatal(err)
	}
	accounts := sqlstore.NewProviderAccountRepository(f.db)
	provider := &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "rollback-subject", "provider@example.com")}
	svc := NewOAuthService(map[string]port.OAuthProvider{"test": provider}, insertThenFailProvider{accounts}, f.users, f.tokens,
		f.hasher, gen, sessions, nil, f.db, OAuthServiceConfig{OAuth: true})
	flow, err := svc.InitiateLink(ctx, api.OAuthLinkInput{Provider: "test", UserID: f.userID, SessionTokenHash: origin.Session.TokenHash})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Callback(ctx, api.OAuthCallbackInput{Provider: "test", Code: "dummy-code", State: flow.State,
		BrowserState: flow.State, SessionToken: origin.SessionToken}); err == nil {
		t.Fatal("expected provider insert failure")
	}
	account, err := accounts.GetByProvider(ctx, "test", "rollback-subject")
	if err != nil || account != nil {
		t.Fatalf("failed finalization retained provider account: %+v err=%v", account, err)
	}
}
