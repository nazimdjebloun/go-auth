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

// stubOAuthProvider is a programmable port.OAuthProvider for driving
// OAuthService.Callback without network access.
type stubOAuthProvider struct {
	name    string
	profile *port.OAuthProfile
	err     error
}

func (p *stubOAuthProvider) Name() string { return p.name }

func (p *stubOAuthProvider) AuthURL(state, _ string) string {
	return "https://provider.test/auth?state=" + state
}

func (p *stubOAuthProvider) Exchange(_ context.Context, _, _ string) (*port.OAuthProfile, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.profile, nil
}

func newTestOAuthService(
	providers map[string]port.OAuthProvider,
	providerRepo port.ProviderAccountRepository,
	users *testutil.MockUserRepo,
	tokens *testutil.MockTokenRepo,
) (*OAuthService, *testutil.MockSessionRepo) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)
	verifySvc := NewVerificationService(users, tokens, gen, nil, &testutil.MockTxManager{}, defaultTestConfig())
	svc := NewOAuthService(
		providers, providerRepo, users, tokens,
		&testutil.MockHasher{}, gen, sessSvc, verifySvc,
		&testutil.MockTxManager{}, OAuthServiceConfig{
			EnableOAuth: true,
		},
	)
	return svc, sessions
}

// seedOAuthState stores a fresh, unused login-flow state token and returns
// the raw state the callback must present.
func seedOAuthState(t *testing.T, tokens *testutil.MockTokenRepo, id, rawState string) {
	t.Helper()
	verifier := "test-code-verifier"
	if err := tokens.Create(context.Background(), &domain.VerificationToken{
		ID:           id,
		TokenHash:    hashToken(rawState),
		Type:         domain.TokenOAuthState,
		ExpiresAt:    time.Now().UTC().Add(10 * time.Minute),
		CodeVerifier: &verifier,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func oauthTestProfile(provider, providerUserID, email string) *port.OAuthProfile {
	return &port.OAuthProfile{
		Provider:       provider,
		ProviderUserID: providerUserID,
		Email:          email,
		EmailVerified:  true,
		Name:           "OAuth User",
	}
}

func TestOAuthCallback_RegistersUserAndLinksProvider(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	providerRepo := testutil.NewMockProviderAccountRepo()
	svc, _ := newTestOAuthService(
		map[string]port.OAuthProvider{
			"test": &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "pu-1", "oauth@example.com")},
		},
		providerRepo, users, tokens,
	)
	seedOAuthState(t, tokens, "state-1", "raw-state-1")

	res, err := svc.Callback(context.Background(), "test", "code", "raw-state-1", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatalf("Callback failed: %v", err)
	}
	if !res.IsNewUser {
		t.Error("expected IsNewUser for a fresh registration")
	}

	user, _ := users.GetByEmail(context.Background(), "oauth@example.com")
	if user == nil {
		t.Fatal("expected the user row to exist")
	}
	accounts, _ := providerRepo.ListByUserID(context.Background(), user.ID)
	if len(accounts) != 1 || accounts[0].ProviderUserID != "pu-1" {
		t.Fatalf("expected one linked provider account, got %+v", accounts)
	}
}

// A provider-account insert failure after the user insert must surface the
// error; atomicity (no orphaned user row) rides on the registration
// transaction, which the sqlstore-backed integration tests pin down.
func TestOAuthCallback_ProviderLinkFailureSurfaces(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	providerRepo := &failingProviderRepo{MockProviderAccountRepo: testutil.NewMockProviderAccountRepo()}
	svc, _ := newTestOAuthService(
		map[string]port.OAuthProvider{
			"test": &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "pu-1", "oauth@example.com")},
		},
		providerRepo, users, tokens,
	)
	seedOAuthState(t, tokens, "state-1", "raw-state-1")

	if _, err := svc.Callback(context.Background(), "test", "code", "raw-state-1", "127.0.0.1", "test-agent"); err == nil {
		t.Fatal("expected the provider failure to surface, got nil")
	}
}

// failingProviderRepo fails account creation to exercise the registration
// transaction's error path.
type failingProviderRepo struct {
	*testutil.MockProviderAccountRepo
}

func (f *failingProviderRepo) Create(_ context.Context, _ *domain.ProviderAccount) error {
	return errors.New("test: provider store unavailable")
}

func TestOAuthUnlink_LastProviderRefusedThenAllowed(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	providerRepo := testutil.NewMockProviderAccountRepo()
	svc, _ := newTestOAuthService(
		map[string]port.OAuthProvider{
			"test":   &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "pu-1", "oauth@example.com")},
			"github": &stubOAuthProvider{name: "github", profile: oauthTestProfile("github", "pu-2", "oauth@example.com")},
		},
		providerRepo, users, tokens,
	)
	ctx := context.Background()

	seedOAuthState(t, tokens, "state-1", "raw-state-1")
	if _, err := svc.Callback(ctx, "test", "code", "raw-state-1", "127.0.0.1", "test-agent"); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	user, _ := users.GetByEmail(ctx, "oauth@example.com")

	// Link the second provider through the link flow: a state token carrying
	// the user ID routes Callback into its link branch.
	seedLinkOAuthState(t, tokens, "link-1", "raw-link-1", user.ID)
	if _, err := svc.Callback(ctx, "github", "code", "raw-link-1", "127.0.0.1", "test-agent"); err != nil {
		t.Fatalf("link failed: %v", err)
	}

	if err := svc.Unlink(ctx, user.ID, "test"); err != nil {
		t.Fatalf("unlink of one of two providers failed: %v", err)
	}
	if err := svc.Unlink(ctx, user.ID, "github"); authErrCode(err) != "cannot_unlink_last_provider" {
		t.Fatalf("unlink of the last provider: code = %q, want cannot_unlink_last_provider", authErrCode(err))
	}

	accounts, _ := providerRepo.ListByUserID(ctx, user.ID)
	if len(accounts) != 1 || accounts[0].Provider != "github" {
		t.Fatalf("expected only the github link to remain, got %+v", accounts)
	}
}

func TestOAuthUnlink_PasswordHolderMayUnlinkLast(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	providerRepo := testutil.NewMockProviderAccountRepo()
	svc, _ := newTestOAuthService(
		map[string]port.OAuthProvider{
			"test": &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "pu-1", "oauth@example.com")},
		},
		providerRepo, users, tokens,
	)
	ctx := context.Background()

	seedOAuthState(t, tokens, "state-1", "raw-state-1")
	if _, err := svc.Callback(ctx, "test", "code", "raw-state-1", "127.0.0.1", "test-agent"); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	user, _ := users.GetByEmail(ctx, "oauth@example.com")

	hash, _ := (&testutil.MockHasher{}).Hash("Passw0rd!")
	user.PasswordHash = &hash
	if err := svc.Unlink(ctx, user.ID, "test"); err != nil {
		t.Fatalf("password holder unlinking last provider failed: %v", err)
	}
}

func TestOAuthUnlink_UnknownUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	providerRepo := testutil.NewMockProviderAccountRepo()
	svc, _ := newTestOAuthService(
		map[string]port.OAuthProvider{
			"test": &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "pu-1", "oauth@example.com")},
		},
		providerRepo, users, tokens,
	)

	if err := svc.Unlink(context.Background(), "missing", "test"); err != domain.ErrUserNotFound {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func seedLinkOAuthState(t *testing.T, tokens *testutil.MockTokenRepo, id, rawState, userID string) {
	t.Helper()
	verifier := "test-code-verifier"
	if err := tokens.Create(context.Background(), &domain.VerificationToken{
		ID:           id,
		UserID:       &userID,
		TokenHash:    hashToken(rawState),
		Type:         domain.TokenOAuthState,
		ExpiresAt:    time.Now().UTC().Add(10 * time.Minute),
		CodeVerifier: &verifier,
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}
