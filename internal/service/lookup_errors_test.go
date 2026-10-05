package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type lookupFaultUsers struct {
	*testutil.MockUserRepo
	err error
}

func (r *lookupFaultUsers) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.MockUserRepo.GetByEmail(ctx, email)
}

func (r *lookupFaultUsers) GetByID(ctx context.Context, id string) (*domain.User, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.MockUserRepo.GetByID(ctx, id)
}

type lookupFaultTokens struct {
	*testutil.MockTokenRepo
	err error
}

func (r *lookupFaultTokens) GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.MockTokenRepo.GetByHash(ctx, hash)
}

func (r *lookupFaultTokens) GetByID(ctx context.Context, id string) (*domain.VerificationToken, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.MockTokenRepo.GetByID(ctx, id)
}

func (r *lookupFaultTokens) GetLastByUserAndType(ctx context.Context, id string, kind domain.TokenType) (*domain.VerificationToken, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.MockTokenRepo.GetLastByUserAndType(ctx, id, kind)
}

func (r *lookupFaultTokens) HasValidByUserAndType(ctx context.Context, id string, kind domain.TokenType) (bool, error) {
	if r.err != nil {
		return false, r.err
	}
	return r.MockTokenRepo.HasValidByUserAndType(ctx, id, kind)
}

type lookupFaultSessions struct {
	*testutil.MockSessionRepo
	err error
}

func (r *lookupFaultSessions) GetByTokenHash(ctx context.Context, hash string) (*domain.Session, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.MockSessionRepo.GetByTokenHash(ctx, hash)
}

func (r *lookupFaultSessions) GetByTokenHashWithUser(ctx context.Context, hash string) (*domain.Session, *domain.User, error) {
	if r.err != nil {
		return nil, nil, r.err
	}
	return r.MockSessionRepo.GetByTokenHashWithUser(ctx, hash)
}

type lookupFaultInvites struct {
	port.InviteRepository
	err error
}

func (r *lookupFaultInvites) GetByCode(context.Context, string) (*domain.Invite, error) {
	return nil, r.err
}

type lookupFaultOrgInvites struct {
	port.OrgInviteRepository
	err error
}

func (r *lookupFaultOrgInvites) GetByCodeHash(context.Context, string) (*domain.OrgInvite, error) {
	return nil, r.err
}

type lookupErrorFixture struct {
	users        *lookupFaultUsers
	tokens       *lookupFaultTokens
	sessions     *lookupFaultSessions
	auth         *AuthService
	password     *PasswordService
	verification *VerificationService
	twoFactor    *TwoFactorService
	oauth        *OAuthService
}

func newLookupErrorFixture(t *testing.T) *lookupErrorFixture {
	t.Helper()
	ctx := context.Background()
	users := &lookupFaultUsers{MockUserRepo: testutil.NewMockUserRepo()}
	tokens := &lookupFaultTokens{MockTokenRepo: testutil.NewMockTokenRepo()}
	sessions := &lookupFaultSessions{MockSessionRepo: testutil.NewMockSessionRepo()}
	if err := users.Create(ctx, &domain.User{ID: "user", Email: "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := sessions.Create(ctx, &domain.Session{
		ID: "session", UserID: "user", TokenHash: hashToken("session"),
		CreatedAt: now, LastActiveAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	cfg := defaultTestConfig()
	cfg.DisableTwoFactorChallengeBinding = true
	userID := "user"
	for _, token := range []domain.VerificationToken{
		{ID: "verify", Type: domain.TokenVerifyEmail, TokenHash: hashOTP("VERIFY23", cfg.OTPPepper)},
		{ID: "reset", Type: domain.TokenResetPass, TokenHash: hashToken("reset")},
		{ID: "challenge", Type: domain.TokenTwoFactor, TokenHash: hashOTP("123456", cfg.OTPPepper)},
		{ID: "state", Type: domain.TokenOAuthState, TokenHash: hashToken("state")},
	} {
		if token.Type != domain.TokenOAuthState {
			token.UserID = &userID
		}
		token.ExpiresAt, token.CreatedAt = now.Add(time.Hour), now
		if err := tokens.Create(ctx, &token); err != nil {
			t.Fatal(err)
		}
	}
	gen := &testutil.MockTokenGen{Length: 32}
	hasher := &testutil.MockHasher{}
	mail := &testutil.MockMailer{}
	tx := &testutil.MockTxManager{}
	sessionSvc := newTestSessionService(sessions, gen)
	return &lookupErrorFixture{
		users: users, tokens: tokens, sessions: sessions,
		auth:         NewAuthService(&testutil.MockTxManager{}, users, sessions, tokens, hasher, gen, mail, cfg, sessionSvc, nil, nil),
		password:     NewPasswordService(users, tokens, hasher, gen, mail, sessions, tx, cfg),
		verification: NewVerificationService(users, tokens, gen, mail, tx, cfg),
		twoFactor:    NewTwoFactorService(&testutil.MockTxManager{}, users, sessions, tokens, hasher, mail, nil, cfg, sessionSvc),
		oauth: NewOAuthService(map[string]port.OAuthProvider{
			"github": &stubOAuthProvider{name: "github", profile: oauthTestProfile("github", "subject", "user@example.com")},
		}, testutil.NewMockProviderAccountRepo(), users, tokens, hasher, gen, sessionSvc, nil, tx, OAuthServiceConfig{EnableOAuth: true}),
	}
}

func TestServiceLookupsPreserveInfrastructureErrors(t *testing.T) {
	for _, failure := range []struct {
		name string
		err  error
	}{
		{"backend failure", errors.New("database unavailable")},
		{"cancellation", context.Canceled},
		{"deadline", context.DeadlineExceeded},
	} {
		t.Run(failure.name, func(t *testing.T) {
			for _, tc := range []struct {
				name string
				kind string
				call func(*lookupErrorFixture) error
			}{
				{"register email", "user", func(f *lookupErrorFixture) error {
					_, err := f.auth.Register(t.Context(), api.RegisterInput{Email: "new@example.com", Password: "Passw0rd!", Name: "User"})
					return err
				}},
				{"login email", "user", func(f *lookupErrorFixture) error {
					_, err := f.auth.Login(t.Context(), api.LoginInput{Email: "user@example.com"})
					return err
				}},
				{"session backend", "session", func(f *lookupErrorFixture) error {
					_, _, err := f.auth.ValidateSession(t.Context(), "session")
					return err
				}},
				{"session user", "user", func(f *lookupErrorFixture) error {
					_, _, err := f.auth.ValidateSession(t.Context(), "session")
					return err
				}},
				{"change name", "user", func(f *lookupErrorFixture) error { return f.auth.ChangeName(t.Context(), "user", "New") }},
				{"delete user", "user", func(f *lookupErrorFixture) error { return f.auth.DeleteAccount(t.Context(), "user", "password") }},
				{"request deletion user", "user", func(f *lookupErrorFixture) error { return f.auth.RequestDeleteAccount(t.Context(), "user") }},
				{"request deletion token", "token", func(f *lookupErrorFixture) error { return f.auth.RequestDeleteAccount(t.Context(), "user") }},
				{"confirm deletion user", "user", func(f *lookupErrorFixture) error {
					return f.auth.ConfirmDeleteAccount(t.Context(), api.ConfirmDeleteAccountInput{UserID: "user"})
				}},
				{"confirm deletion token", "token", func(f *lookupErrorFixture) error {
					return f.auth.ConfirmDeleteAccount(t.Context(), api.ConfirmDeleteAccountInput{UserID: "user"})
				}},
				{"reset token", "token", func(f *lookupErrorFixture) error {
					return f.password.ResetPassword(t.Context(), api.ResetPasswordInput{Code: "reset", NewPassword: "Passw0rd!"})
				}},
				{"reset user", "user", func(f *lookupErrorFixture) error {
					return f.password.ResetPassword(t.Context(), api.ResetPasswordInput{Code: "reset", NewPassword: "Passw0rd!"})
				}},
				{"request password user", "user", func(f *lookupErrorFixture) error { return f.password.RequestSetPassword(t.Context(), "user") }},
				{"confirm password user", "user", func(f *lookupErrorFixture) error {
					return f.password.ConfirmSetPassword(t.Context(), api.ConfirmSetPasswordInput{UserID: "user", NewPassword: "Passw0rd!"})
				}},
				{"confirm password token", "token", func(f *lookupErrorFixture) error {
					return f.password.ConfirmSetPassword(t.Context(), api.ConfirmSetPasswordInput{UserID: "user", NewPassword: "Passw0rd!"})
				}},
				{"change password user", "user", func(f *lookupErrorFixture) error {
					return f.password.ChangePassword(t.Context(), api.ChangePasswordInput{UserID: "user"})
				}},
				{"verify email token", "token", func(f *lookupErrorFixture) error {
					_, err := f.verification.VerifyEmail(t.Context(), "VERIFY23")
					return err
				}},
				{"verify email user", "user", func(f *lookupErrorFixture) error {
					_, err := f.verification.VerifyEmail(t.Context(), "VERIFY23")
					return err
				}},
				{"resend verification user", "user", func(f *lookupErrorFixture) error {
					_, err := f.verification.ResendVerification(t.Context(), "user")
					return err
				}},
				{"verify 2fa token", "token", func(f *lookupErrorFixture) error {
					_, err := f.twoFactor.Verify(t.Context(), "challenge", "", "123456", "", "")
					return err
				}},
				{"resend 2fa token", "token", func(f *lookupErrorFixture) error {
					_, err := f.twoFactor.Resend(t.Context(), "challenge", "")
					return err
				}},
				{"resend 2fa user", "user", func(f *lookupErrorFixture) error {
					_, err := f.twoFactor.Resend(t.Context(), "challenge", "")
					return err
				}},
				{"change 2fa user", "user", func(f *lookupErrorFixture) error {
					_, err := f.twoFactor.authorizeChange(t.Context(), "user", "password")
					return err
				}},
				{"oauth state", "token", func(f *lookupErrorFixture) error {
					_, err := f.oauth.Callback(t.Context(), "github", "code", "state", "state", "", "", "")
					return err
				}},
				{"oauth linking session", "session", func(f *lookupErrorFixture) error {
					state, err := f.tokens.GetByHash(t.Context(), hashToken("state"))
					if err != nil {
						return err
					}
					userID := "user"
					state.UserID, state.Email = &userID, hashToken("session")
					_, err = f.oauth.Callback(t.Context(), "github", "code", "state", "state", "session", "", "")
					return err
				}},
				{"oauth email", "user", func(f *lookupErrorFixture) error {
					_, err := f.oauth.Callback(t.Context(), "github", "code", "state", "state", "", "", "")
					return err
				}},
				{"invite lookup", "", func(_ *lookupErrorFixture) error {
					svc := &InviteService{invites: &lookupFaultInvites{err: failure.err}}
					_, err := svc.GetInviteByToken(t.Context(), "code")
					return err
				}},
				{"invite registration", "", func(_ *lookupErrorFixture) error {
					svc := &InviteService{config: defaultTestConfig(), invites: &lookupFaultInvites{err: failure.err}}
					_, err := svc.CompleteInviteRegistration(t.Context(), api.CompleteInviteInput{Code: "code"})
					return err
				}},
				{"org invite token", "", func(f *lookupErrorFixture) error {
					svc := &OrgInviteService{users: f.users, orgInvites: &lookupFaultOrgInvites{err: failure.err}}
					return svc.AcceptInvite(t.Context(), api.AcceptInviteInput{UserID: "user", RawCode: "code"})
				}},
				{"org invite user", "user", func(f *lookupErrorFixture) error {
					svc := &OrgInviteService{users: f.users}
					return svc.AcceptInvite(t.Context(), api.AcceptInviteInput{UserID: "user"})
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := newLookupErrorFixture(t)
					switch tc.kind {
					case "user":
						f.users.err = failure.err
					case "token":
						f.tokens.err = failure.err
					case "session":
						f.sessions.err = failure.err
					}
					if err := tc.call(f); !errors.Is(err, failure.err) {
						t.Fatalf("error = %v, want preserved cause %v", err, failure.err)
					}
				})
			}
		})
	}
}

func TestValidateSessionMissingStillReturnsSessionExpired(t *testing.T) {
	f := newLookupErrorFixture(t)
	_, _, err := f.auth.ValidateSession(t.Context(), "missing")
	if !errors.Is(err, domain.ErrSessionExpired) {
		t.Fatalf("missing session = %v, want session_expired", err)
	}
}
