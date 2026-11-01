package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/crypto"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func policyTwoFactor(t *testing.T, f *passwordTransactionFixture) (*TwoFactorService, *testutil.MockMailer, string) {
	t.Helper()
	cfg := defaultTestConfig()
	cfg.TwoFactorCodeTTL = 5 * time.Minute
	cfg.DisableAdminTwoFactor = true
	cfg.PasswordAuthenticationDisabled = true
	cfg.TwoFactorBindingKey = []byte("test-binding-key-32-bytes-long!!!")
	mailer := &testutil.MockMailer{}
	sessions := NewSessionService(f.db, f.sessions, &testutil.MockTokenGen{Length: 32}, DefaultSessionConfig())
	svc := NewTwoFactorService(f.db, f.users, f.sessions, f.tokens, f.hasher, mailer, nil, cfg, sessions)
	svc.AttachSettingsSessions(f.sessions)
	session, err := f.sessions.GetByTokenHash(t.Context(), f.session)
	if err != nil {
		t.Fatal(err)
	}
	return svc, mailer, session.ID
}

func TestTwoFactorSettingsProofIsBoundAndOneTime(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	svc, mailer, sessionID := policyTwoFactor(t, f)
	ctx := t.Context()
	request := api.TwoFactorSettingsChallengeInput{UserID: f.userID, CallerSessionID: sessionID, Action: "enable"}
	proof, err := svc.RequestSettingsChallenge(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	code := testutil.GetLastVerificationCode(mailer)
	again, err := svc.RequestSettingsChallenge(ctx, request)
	if err != nil || again.ID != proof.ID || again.Sent || mailer.SentCount() != 1 {
		t.Fatalf("challenge was resent/reset: %+v %v", again, err)
	}
	if err := svc.Disable(ctx, api.TwoFactorDisableInput{UserID: f.userID, CallerSessionID: sessionID, ChallengeID: proof.ID, Code: code}); !errors.Is(err, domain.ErrTwoFactorCodeInvalid) {
		t.Fatalf("cross-action proof accepted: %v", err)
	}
	other, err := svc.sessionSvc.Create(ctx, api.CreateSessionInput{UserID: f.userID})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Enable(ctx, api.TwoFactorEnableInput{UserID: f.userID, CallerSessionID: other.Session.ID, ChallengeID: proof.ID, Code: code}); !errors.Is(err, domain.ErrTwoFactorCodeInvalid) {
		t.Fatalf("cross-session proof accepted: %v", err)
	}
	if err := svc.Enable(ctx, api.TwoFactorEnableInput{UserID: f.userID, Password: "OldPass1!", CallerSessionID: sessionID}); !errors.Is(err, domain.ErrMethodDisabled) {
		t.Fatalf("disabled password method authorized settings: %v", err)
	}
	if err := svc.Enable(ctx, api.TwoFactorEnableInput{UserID: f.userID, CallerSessionID: sessionID, ChallengeID: proof.ID, Code: code}); err != nil {
		t.Fatal(err)
	}
	user, err := f.users.GetByID(ctx, f.userID)
	if err != nil || !user.TwoFactorEnabled {
		t.Fatalf("setting not applied: %+v %v", user, err)
	}
	if err := svc.Enable(ctx, api.TwoFactorEnableInput{UserID: f.userID, CallerSessionID: sessionID, ChallengeID: proof.ID, Code: code}); !errors.Is(err, domain.ErrTwoFactorCodeInvalid) {
		t.Fatalf("proof reused: %v", err)
	}
}

func TestTwoFactorSettingsProofCapsRevocationAndPolicy(t *testing.T) {
	for _, name := range []string{"attempt cap", "revoked session", "email changed", "mandatory policy", "wrong scope"} {
		t.Run(name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			svc, mailer, sessionID := policyTwoFactor(t, f)
			ctx := t.Context()
			proof, err := svc.RequestSettingsChallenge(ctx, api.TwoFactorSettingsChallengeInput{UserID: f.userID, CallerSessionID: sessionID, Action: "enable"})
			if err != nil {
				t.Fatal(err)
			}
			code := testutil.GetLastVerificationCode(mailer)
			input := api.TwoFactorEnableInput{UserID: f.userID, CallerSessionID: sessionID, ChallengeID: proof.ID, Code: code}
			switch name {
			case "attempt cap":
				for range maxAttemptsPerChallenge {
					bad := input
					bad.Code = "bad"
					if err := svc.Enable(ctx, bad); !errors.Is(err, domain.ErrTwoFactorCodeInvalid) {
						t.Fatal(err)
					}
				}
				token, err := f.tokens.GetByID(ctx, proof.ID)
				if err != nil || token.Attempts != maxAttemptsPerChallenge {
					t.Fatalf("failed attempts rolled back: %+v %v", token, err)
				}
			case "revoked session":
				if err := f.sessions.DeleteByID(ctx, sessionID); err != nil {
					t.Fatal(err)
				}
			case "email changed":
				if _, err := f.db.ExecContext(ctx, "UPDATE users SET email=$1 WHERE id=$2", "changed@example.com", f.userID); err != nil {
					t.Fatal(err)
				}
			case "mandatory policy":
				svc.config.RequireEmail2FA = true
			case "wrong scope":
				ctx = sessioncontext.With(ctx, sessioncontext.Admin)
			}
			if err := svc.Enable(ctx, input); err == nil {
				t.Fatal("invalid proof changed preference")
			}
			user, err := f.users.GetByID(t.Context(), f.userID)
			if err != nil || user.TwoFactorEnabled {
				t.Fatalf("invalid confirmation mutated account: %+v %v", user, err)
			}
		})
	}
}

type oauthInviteFixture struct {
	f        *passwordTransactionFixture
	svc      *OAuthService
	provider *stubOAuthProvider
	invites  *sqlstore.InviteRepository
	mailer   *testutil.MockMailer
	invite   *domain.Invite
	raw      string
}

func newOAuthInviteFixture(t *testing.T, verified bool) oauthInviteFixture {
	t.Helper()
	f := newPasswordTransactionFixture(t)
	twoFactor, mailer, _ := policyTwoFactor(t, f)
	enc, err := crypto.NewEncryptor([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	profile := oauthTestProfile("test", "invited-subject", "invited@example.com")
	profile.EmailVerified = verified
	profile.AccessToken = "private-provider-access-token"
	provider := &stubOAuthProvider{name: "test", profile: profile}
	invites := sqlstore.NewInviteRepository(f.db)
	now := time.Now().UTC()
	raw := "raw-invitation-token"
	invite := &domain.Invite{ID: generateID(), Email: profile.Email, Code: hashToken(raw), CreatedBy: f.userID, Status: domain.InvitePending, ExpiresAt: now.Add(time.Hour), CreatedAt: now}
	if err := invites.Create(t.Context(), invite); err != nil {
		t.Fatal(err)
	}
	cfg := OAuthServiceConfig{CommonConfig: defaultTestConfig().CommonConfig, OAuth: true, InviteSignup: true, InviteOnly: true, Encryptor: enc, DisableAdminTwoFactor: true}
	svc := NewOAuthService(map[string]port.OAuthProvider{"test": provider}, sqlstore.NewProviderAccountRepository(f.db), f.users, f.tokens, f.hasher, &testutil.MockTokenGen{Length: 32}, twoFactor.sessionSvc, nil, f.db, cfg)
	svc.AttachInvites(invites)
	svc.AttachTwoFactor(twoFactor)
	return oauthInviteFixture{f: f, svc: svc, provider: provider, invites: invites, mailer: mailer, invite: invite, raw: raw}
}

func (f oauthInviteFixture) callback(t *testing.T) (*api.OAuthCallbackResult, error) {
	t.Helper()
	flow, err := f.svc.InitiateInvite(t.Context(), api.OAuthInviteInput{Provider: "test", InviteToken: f.raw})
	if err != nil {
		return nil, err
	}
	return f.svc.Callback(t.Context(), api.OAuthCallbackInput{Provider: "test", State: flow.State, BrowserState: flow.State, Code: "provider-code"})
}

func TestOAuthInvitationCreatesAccountOnlyAfterEmailProof(t *testing.T) {
	for _, verified := range []bool{true, false} {
		name := "provider verified"
		if !verified {
			name = "email code required"
		}
		t.Run(name, func(t *testing.T) {
			f := newOAuthInviteFixture(t, verified)
			result, err := f.callback(t)
			if err != nil {
				t.Fatal(err)
			}
			if !verified {
				if !result.RequiresInviteVerification || result.SessionToken != "" {
					t.Fatalf("missing pre-account proof: %+v", result)
				}
				user, err := f.f.users.GetByEmail(t.Context(), f.invite.Email)
				if err != nil || user != nil {
					t.Fatalf("account created before verification: %+v %v", user, err)
				}
				token, err := f.f.tokens.GetByID(t.Context(), result.InviteChallengeID)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(token.EncryptedPayload, f.provider.profile.AccessToken) {
					t.Fatal("pending provider token stored in plaintext")
				}
				input := api.OAuthInviteVerifyInput{ChallengeID: result.InviteChallengeID, BindingToken: result.BindingToken(), Code: testutil.GetLastVerificationCode(f.mailer)}
				bad := input
				bad.BindingToken = "wrong"
				if _, err := f.svc.VerifyInviteEmail(t.Context(), bad); !errors.Is(err, domain.ErrVerificationCodeInvalid) {
					t.Fatalf("unbound proof accepted: %v", err)
				}
				if _, err := f.svc.VerifyInviteEmail(sessioncontext.With(t.Context(), sessioncontext.Admin), input); err == nil {
					t.Fatal("invitation proof crossed into admin scope")
				}
				result, err = f.svc.VerifyInviteEmail(t.Context(), input)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.svc.VerifyInviteEmail(t.Context(), input); !errors.Is(err, domain.ErrVerificationCodeInvalid) {
					t.Fatalf("proof reused: %v", err)
				}
			}
			if result.SessionToken == "" || !result.IsNewUser {
				t.Fatalf("missing completed signup: %+v", result)
			}
			invite, err := f.invites.GetByID(t.Context(), f.invite.ID)
			if err != nil || invite.Status != domain.InviteAccepted {
				t.Fatalf("invitation not consumed: %+v %v", invite, err)
			}
			user, err := f.f.users.GetByEmail(t.Context(), f.invite.Email)
			if err != nil || user == nil || !user.IsVerified {
				t.Fatalf("wrong account state: %+v %v", user, err)
			}
		})
	}
}

func TestOAuthInvitationRejectsWrongRecipientAndChangedPolicy(t *testing.T) {
	for _, name := range []string{"wrong recipient", "revoked", "rotated", "expired", "signup disabled", "OAuth disabled", "public still closed"} {
		t.Run(name, func(t *testing.T) {
			f := newOAuthInviteFixture(t, true)
			flow, err := f.svc.InitiateInvite(t.Context(), api.OAuthInviteInput{Provider: "test", InviteToken: f.raw})
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "wrong recipient":
				f.provider.profile.Email = "other@example.com"
			case "revoked":
				if _, err := f.invites.Revoke(t.Context(), f.invite.ID); err != nil {
					t.Fatal(err)
				}
			case "rotated":
				if _, err := f.invites.RotateCode(t.Context(), f.invite.ID, f.invite.Code, hashToken("replacement"), time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := f.f.db.ExecContext(t.Context(), "UPDATE invites SET expires_at=$1 WHERE id=$2", time.Now().Add(-time.Hour), f.invite.ID); err != nil {
					t.Fatal(err)
				}
			case "signup disabled":
				f.svc.config.InviteSignup = false
			case "OAuth disabled":
				f.svc.config.OAuthAuthenticationDisabled = true
			case "public still closed":
				flow, err = f.svc.Initiate(t.Context(), "test")
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.svc.Callback(t.Context(), api.OAuthCallbackInput{Provider: "test", State: flow.State, BrowserState: flow.State, Code: "code"}); err == nil {
				t.Fatal("invalid invitation signup succeeded")
			}
			user, err := f.f.users.GetByEmail(t.Context(), "invited@example.com")
			if err != nil || user != nil {
				t.Fatalf("failed flow created an account: %+v %v", user, err)
			}
		})
	}
}

// A failed provider insert must roll back both the invitation and provisional user.
type failingSQLProviderInsert struct{ port.ProviderAccountRepository }

func (f failingSQLProviderInsert) Create(context.Context, *domain.ProviderAccount) error {
	return errors.New("provider insert failed")
}

func TestOAuthInvitationProviderFailureRollsBackProofAndClaim(t *testing.T) {
	f := newOAuthInviteFixture(t, false)
	result, err := f.callback(t)
	if err != nil {
		t.Fatal(err)
	}
	input := api.OAuthInviteVerifyInput{ChallengeID: result.InviteChallengeID, BindingToken: result.BindingToken(), Code: testutil.GetLastVerificationCode(f.mailer)}
	original := f.svc.providerRepo
	f.svc.providerRepo = failingSQLProviderInsert{original}
	if _, err := f.svc.VerifyInviteEmail(t.Context(), input); err == nil {
		t.Fatal("provider failure ignored")
	}
	invite, err := f.invites.GetByID(t.Context(), f.invite.ID)
	if err != nil || invite.Status != domain.InvitePending {
		t.Fatalf("failed transaction consumed invitation: %+v %v", invite, err)
	}
	proof, err := f.f.tokens.GetByID(t.Context(), input.ChallengeID)
	if err != nil || proof.UsedAt != nil {
		t.Fatalf("failed transaction consumed proof: %+v %v", proof, err)
	}
	user, err := f.f.users.GetByEmail(t.Context(), f.invite.Email)
	if err != nil || user != nil {
		t.Fatalf("failed transaction left account: %+v %v", user, err)
	}
	f.svc.providerRepo = original
	if _, err := f.svc.VerifyInviteEmail(t.Context(), input); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
}

func TestTwoFactorLoginChallengeRechecksAuthenticationMethod(t *testing.T) {
	for _, method := range []string{"password", "oauth"} {
		t.Run(method, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			svc, mailer, _ := policyTwoFactor(t, f)
			svc.config.PasswordAuthenticationDisabled = false
			user, err := f.users.GetByID(t.Context(), f.userID)
			if err != nil {
				t.Fatal(err)
			}
			var challenge *api.ChallengeResult
			if method == "password" {
				challenge, err = svc.challengeWithPassword(t.Context(), user)
			} else {
				challenge, err = svc.challengeWithOAuth(t.Context(), user.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if method == "password" {
				svc.config.PasswordAuthenticationDisabled = true
			} else {
				svc.config.OAuthAuthenticationDisabled = true
			}
			_, err = svc.Verify(t.Context(), api.TwoFactorVerifyInput{ChallengeID: challenge.ID, BindingToken: challenge.BindingToken, Code: testutil.GetLastVerificationCode(mailer)})
			if !errors.Is(err, domain.ErrMethodDisabled) {
				t.Fatalf("disabled first factor completed login: %v", err)
			}
		})
	}
}

func TestOAuthInvitationNormalizesEmailAndRejectsWrongProvider(t *testing.T) {
	f := newOAuthInviteFixture(t, false)
	f.provider.profile.Email = " INVITED@EXAMPLE.COM "
	result, err := f.callback(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.VerifyInviteEmail(t.Context(), api.OAuthInviteVerifyInput{ChallengeID: result.InviteChallengeID, BindingToken: result.BindingToken(), Code: testutil.GetLastVerificationCode(f.mailer)}); err != nil {
		t.Fatalf("matching address normalization: %v", err)
	}
	g := newOAuthInviteFixture(t, true)
	flow, err := g.svc.Initiate(t.Context(), "test")
	if err != nil {
		t.Fatal(err)
	}
	g.svc.providers["other"] = &stubOAuthProvider{name: "other", profile: oauthTestProfile("other", "other-subject", "other@example.test")}
	if _, err := g.svc.Callback(t.Context(), api.OAuthCallbackInput{Provider: "other", State: flow.State, BrowserState: flow.State, Code: "code"}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("OAuth state crossed providers: %v", err)
	}
}
