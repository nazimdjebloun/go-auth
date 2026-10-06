package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
)

type mockOAuthProvider struct {
	name    string
	profile *port.OAuthProfile
	err     error
}

func (m *mockOAuthProvider) Name() string { return m.name }

func (m *mockOAuthProvider) AuthURL(state, challenge string) string {
	return "https://provider.com/auth?state=" + state + "&challenge=" + challenge
}

func (m *mockOAuthProvider) Exchange(_ context.Context, _, _ string) (*port.OAuthProfile, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.profile, nil
}

type mockProviderAccountRepo struct {
	mu       sync.Mutex
	accounts map[string]*domain.ProviderAccount
}

func newMockProviderAccountRepo() *mockProviderAccountRepo {
	return &mockProviderAccountRepo{accounts: make(map[string]*domain.ProviderAccount)}
}

func (m *mockProviderAccountRepo) Create(_ context.Context, pa *domain.ProviderAccount) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := pa.Provider + ":" + pa.ProviderUserID
	m.accounts[key] = pa
	return nil
}

func (m *mockProviderAccountRepo) GetByProvider(_ context.Context, provider, providerUserID string) (*domain.ProviderAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pa, ok := m.accounts[provider+":"+providerUserID]
	if !ok {
		return nil, nil
	}
	return pa, nil
}

func (m *mockProviderAccountRepo) ListByUserID(_ context.Context, userID string) ([]domain.ProviderAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []domain.ProviderAccount
	for _, pa := range m.accounts {
		if pa.UserID == userID {
			result = append(result, *pa)
		}
	}
	return result, nil
}

func (m *mockProviderAccountRepo) Delete(_ context.Context, userID, provider string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, pa := range m.accounts {
		if pa.UserID == userID && pa.Provider == provider {
			delete(m.accounts, key)
		}
	}
	return nil
}

// LockByUserID is a no-op here for the same reason as in testutil's mock:
// the in-memory map serializes through its own mutex, and handler tests
// run sequential guard-then-delete sequences.
func (m *mockProviderAccountRepo) LockByUserID(_ context.Context, _ string) error {
	return nil
}

type oauthTestHarness struct {
	oauthHandlers    *OAuthHandlers
	sessionSvc       *service.SessionService
	oauthSvc         *service.OAuthService
	mockProvider     *mockOAuthProvider
	providerRepo     *mockProviderAccountRepo
	userRepo         *mockUserRepo
	tokenRepo        *mockTokenRepo
	sessionRepo      *mockSessionRepo
	baseURL          string
	sid              string
	stateToken       string
	linkSessionToken string
}

func (th *oauthTestHarness) callback(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	if state != "" {
		r.AddCookie(th.oauthHandlers.oauthStateCookie(state, 600))
	}
	if th.linkSessionToken != "" {
		r.AddCookie(&http.Cookie{
			Name: th.oauthHandlers.cookies.Name, Value: th.linkSessionToken,
			Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		})
	}
	th.oauthHandlers.Callback(w, r)
}

func (th *oauthTestHarness) createStateToken(t testing.TB, rawState string) string {
	stateHash := sha256.Sum256([]byte(rawState))
	verifier := "test-code-verifier-value"
	sid := "state-" + rawState

	stateToken := &domain.VerificationToken{
		ID:           sid,
		TokenHash:    hex.EncodeToString(stateHash[:]),
		Type:         domain.TokenOAuthState,
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
		CodeVerifier: &verifier,
	}
	checkTestErrors(t).noError(th.tokenRepo.Create(context.Background(), stateToken))
	return rawState
}

// createLinkStateToken mints a state token carrying userID, matching what
// OAuthService.InitiateLink produces — this is what routes a callback into
// Callback's link branch instead of its login/register branch.
func (th *oauthTestHarness) createLinkStateToken(t testing.TB, rawState, userID string) string {
	sess, err := th.sessionSvc.Create(context.Background(), api.CreateSessionInput{
		UserID:    userID,
		IP:        "127.0.0.1",
		UserAgent: "test-agent",
	})
	checkTestErrors(t).noError(err)
	th.linkSessionToken = sess.SessionToken
	stateHash := sha256.Sum256([]byte(rawState))
	verifier := "test-code-verifier-value"
	sid := "link-state-" + rawState

	stateToken := &domain.VerificationToken{
		ID:           sid,
		UserID:       &userID,
		Email:        sess.Session.TokenHash,
		TokenHash:    hex.EncodeToString(stateHash[:]),
		Type:         domain.TokenOAuthState,
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
		CodeVerifier: &verifier,
	}
	checkTestErrors(t).noError(th.tokenRepo.Create(context.Background(), stateToken))
	return rawState
}

func newOAuthTestHarness(t testing.TB) *oauthTestHarness {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	sessions.users = users
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{}
	mailer := &mockMailer{}

	cfg := service.Config{
		CommonConfig: service.CommonConfig{
			AppName:    "TestApp",
			SessionTTL: 30 * 24 * time.Hour,
			TokenTTL:   1 * time.Hour,
		},
		InviteTTL: 7 * 24 * time.Hour,
	}

	sessCfg := service.DefaultSessionConfig()
	sessCfg.Duration = 30 * 24 * time.Hour
	sessSvc := service.NewSessionService(&inlineTxManager{}, sessions, gen, sessCfg)
	verifySvc := service.NewVerificationService(users, tokens, gen, mailer, &inlineTxManager{}, cfg)

	providerRepo := newMockProviderAccountRepo()

	profile := &port.OAuthProfile{
		Provider:       "test",
		ProviderUserID: "provider-user-123",
		Email:          "oauth-user@example.com",
		EmailVerified:  true,
		Name:           "OAuth User",
		AccessToken:    "access-token",
		RefreshToken:   "refresh-token",
	}

	mockProvider := &mockOAuthProvider{
		name:    "test",
		profile: profile,
	}

	oauthCfg := service.OAuthServiceConfig{
		CommonConfig: service.CommonConfig{
			BaseURL:    "http://localhost:3000",
			AppName:    "TestApp",
			SessionTTL: 30 * 24 * time.Hour,
			TokenTTL:   1 * time.Hour,
		},
		EnableOAuth:              true,
		RequireEmailVerification: false,
	}

	oauthSvc := service.NewOAuthService(
		map[string]port.OAuthProvider{"test": mockProvider, "google": mockProvider, "github": mockProvider},
		providerRepo,
		users,
		tokens,
		hasher,
		gen,
		sessSvc,
		verifySvc,
		&inlineTxManager{},
		oauthCfg,
	)

	oauthHandlers := NewOAuthHandlers(oauthSvc, "http://localhost:3000", nil, middleware.ClientIPConfig{}, middleware.DefaultCookieSettings(), nil)

	stateRaw := "test-state-token-value"
	stateHash := sha256.Sum256([]byte(stateRaw))
	verifier := "test-code-verifier-value"
	sid := "state-token-id"

	stateToken := &domain.VerificationToken{
		ID:           sid,
		TokenHash:    hex.EncodeToString(stateHash[:]),
		Type:         domain.TokenOAuthState,
		ExpiresAt:    time.Now().UTC().Add(1 * time.Hour),
		CodeVerifier: &verifier,
	}
	checkTestErrors(t).noError(tokens.Create(context.Background(), stateToken))

	return &oauthTestHarness{
		oauthHandlers: oauthHandlers,
		sessionSvc:    sessSvc,
		oauthSvc:      oauthSvc,
		mockProvider:  mockProvider,
		providerRepo:  providerRepo,
		userRepo:      users,
		tokenRepo:     tokens,
		sessionRepo:   sessions,
		baseURL:       "http://localhost:3000",
		sid:           sid,
		stateToken:    stateRaw,
	}
}

func TestOAuthCallback_GET_Success(t *testing.T) {
	th := newOAuthTestHarness(t)

	u := fmt.Sprintf("/auth/oauth/test/callback?code=auth-code&state=%s", th.stateToken)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()

	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "window.location.replace") {
		t.Error("expected JS redirect in body")
	}

	cookies := res.Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "goauth_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Error("expected goauth_session cookie")
	} else if sessionCookie.Value == "" {
		t.Error("expected non-empty session cookie value")
	}
}

func TestOAuthInitiate_SetsBrowserStateCookie(t *testing.T) {
	th := newOAuthTestHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/test", nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	th.oauthHandlers.Initiate(w, req)
	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("initiate status = %d", res.StatusCode)
	}
	var body struct {
		URL string `json:"url"`
	}
	mustDecodeJSON(res.Body, &body)
	parsed, err := url.Parse(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		t.Fatal("authorization URL has no state")
	}
	cookies := res.Cookies()
	if len(cookies) != 1 || cookies[0].Value != state || !strings.HasPrefix(cookies[0].Name, "__Host-") ||
		!cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteNoneMode ||
		cookies[0].Domain != "" || cookies[0].Path != "/" || cookies[0].MaxAge != 600 {
		t.Fatalf("browser state cookie misconfigured: %+v", cookies)
	}
}

func TestOAuthCallback_WithoutBrowserCookieRejectsState(t *testing.T) {
	th := newOAuthTestHarness(t)
	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/test/callback?code=auth-code&state="+th.stateToken, nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	th.oauthHandlers.Callback(w, req)
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "error=invalid_state") {
		t.Fatalf("unbound callback: status=%d location=%q", w.Code, w.Header().Get("Location"))
	}
	state, err := th.tokenRepo.GetByID(context.Background(), th.sid)
	if err != nil || state.UsedAt != nil {
		t.Fatalf("unbound callback consumed state: state=%+v err=%v", state, err)
	}
}

func TestOAuthCallback_GET_Success_SecurityHeaders(t *testing.T) {
	th := newOAuthTestHarness(t)

	u := fmt.Sprintf("/auth/oauth/test/callback?code=auth-code&state=%s", th.stateToken)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()

	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	if got := res.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got %q", got)
	}
	if got := res.Header.Get("Content-Security-Policy"); got == "" {
		t.Error("expected a non-empty Content-Security-Policy header")
	}
}

func TestOAuthCallback_POST_Success(t *testing.T) {
	th := newOAuthTestHarness(t)

	form := url.Values{"code": {"auth-code"}, "state": {th.stateToken}}
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth/test/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()

	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "window.location.replace") {
		t.Error("expected JS redirect in body")
	}

	cookies := res.Cookies()
	var sessionCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "goauth_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Error("expected goauth_session cookie")
	} else if sessionCookie.Value == "" {
		t.Error("expected non-empty session cookie value")
	}
}

func TestOAuthCallback_GETandPOST_SameBehavior(t *testing.T) {
	th := newOAuthTestHarness(t)

	getState := th.createStateToken(t, "get-state-for-same-behavior")
	postState := th.createStateToken(t, "post-state-for-same-behavior")

	getURL := fmt.Sprintf("/auth/oauth/test/callback?code=auth-code&state=%s", getState)
	getReq := httptest.NewRequest(http.MethodGet, getURL, nil)
	getReq.SetPathValue("provider", "test")
	getW := httptest.NewRecorder()
	th.callback(getW, getReq)

	postForm := url.Values{"code": {"auth-code"}, "state": {postState}}
	postReq := httptest.NewRequest(http.MethodPost, "/auth/oauth/test/callback", strings.NewReader(postForm.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.SetPathValue("provider", "test")
	postW := httptest.NewRecorder()
	th.callback(postW, postReq)

	getRes, postRes := getW.Result(), postW.Result()
	defer func() { _ = getRes.Body.Close() }()
	defer func() { _ = postRes.Body.Close() }()

	if getRes.StatusCode != postRes.StatusCode {
		t.Errorf("status mismatch: GET=%d POST=%d", getRes.StatusCode, postRes.StatusCode)
	}
	if getRes.StatusCode != http.StatusOK {
		t.Fatalf("both should succeed, got GET=%d POST=%d", getRes.StatusCode, postRes.StatusCode)
	}

	getCookies := getRes.Cookies()
	postCookies := postRes.Cookies()
	if len(getCookies) != len(postCookies) {
		t.Errorf("cookie count mismatch: GET=%d POST=%d", len(getCookies), len(postCookies))
	}

	if len(getCookies) != 3 {
		t.Errorf("expected 3 cookies (state clear, session, refresh), got %d (GET)", len(getCookies))
	}
	if len(postCookies) != 3 {
		t.Errorf("expected 3 cookies (state clear, session, refresh), got %d (POST)", len(postCookies))
	}
}

func TestOAuthCallback_AppleFormPost(t *testing.T) {
	th := newOAuthTestHarness(t)

	form := url.Values{"code": {"apple-code"}, "state": {th.stateToken}}
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth/apple/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()

	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "window.location.replace") {
		t.Error("expected JS redirect in body")
	}
}

func TestOAuthCallback_MissingCode(t *testing.T) {
	th := newOAuthTestHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/test/callback?state="+th.stateToken, nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("expected invalid_request error, got %s", loc)
	}
}

func TestOAuthCallback_MissingState(t *testing.T) {
	th := newOAuthTestHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/test/callback?code=auth-code", nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("expected invalid_request error, got %s", loc)
	}
}

func TestOAuthCallback_EmptyPostBody(t *testing.T) {
	th := newOAuthTestHarness(t)

	req := httptest.NewRequest(http.MethodPost, "/auth/oauth/test/callback", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("expected invalid_request error, got %s", loc)
	}
}

func TestOAuthCallback_POSTMissingBoth(t *testing.T) {
	th := newOAuthTestHarness(t)

	form := url.Values{"foo": {"bar"}}
	req := httptest.NewRequest(http.MethodPost, "/auth/oauth/test/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
}

func TestOAuthCallback_ProviderError(t *testing.T) {
	th := newOAuthTestHarness(t)
	th.mockProvider.err = fmt.Errorf("provider: exchange failed")

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/oauth/test/callback?code=bad-code&state=%s", th.stateToken), nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "error=provider_error") {
		t.Errorf("expected provider_error, got %s", loc)
	}
}

func TestOAuthCallback_InvalidProvider(t *testing.T) {
	th := newOAuthTestHarness(t)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/nonexistent/callback?code=abc&state=xyz", nil)
	req.SetPathValue("provider", "nonexistent")
	w := httptest.NewRecorder()
	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "error=provider_not_found") {
		t.Errorf("expected provider_not_found, got %s", loc)
	}
}

func TestOAuthCallback_Disabled(t *testing.T) {
	h := NewOAuthHandlers(nil, "http://localhost:3000", nil, middleware.ClientIPConfig{}, middleware.DefaultCookieSettings(), nil)

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/test/callback?code=abc&state=xyz", nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	h.Callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
	var body map[string]string
	mustDecodeJSON(res.Body, &body)
	if body["error"] != "provider_not_found" {
		t.Errorf("expected provider_not_found, got %s", body["error"])
	}
}

func TestOAuthCallback_StateAlreadyUsed(t *testing.T) {
	th := newOAuthTestHarness(t)

	now := time.Now().UTC()
	th.tokenRepo.tokens[th.sid].UsedAt = &now

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/oauth/test/callback?code=abc&state=%s", th.stateToken), nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "error=state_used") {
		t.Errorf("expected state_used, got %s", loc)
	}
}

func TestOAuthCallback_StateExpired(t *testing.T) {
	th := newOAuthTestHarness(t)

	th.tokenRepo.tokens[th.sid].ExpiresAt = time.Now().UTC().Add(-1 * time.Hour)

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/auth/oauth/test/callback?code=abc&state=%s", th.stateToken), nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()
	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "error=state_expired") {
		t.Errorf("expected state_expired, got %s", loc)
	}
}

func TestOAuthCallback_GETWithPOSTBody(t *testing.T) {
	th := newOAuthTestHarness(t)

	form := url.Values{"code": {"body-code"}, "state": {th.stateToken}}
	body := form.Encode()

	req := httptest.NewRequest(http.MethodGet, "/auth/oauth/test/callback", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()

	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 (GET ignores body), got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.Contains(loc, "error=invalid_request") {
		t.Errorf("expected invalid_request, got %s", loc)
	}
}

func TestOAuthCallback_GoogleGET(t *testing.T) {
	th := newOAuthTestHarness(t)
	th.mockProvider.profile.Provider = "google"

	u := fmt.Sprintf("/auth/oauth/google/callback?code=google-code&state=%s", th.stateToken)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	req.SetPathValue("provider", "google")
	w := httptest.NewRecorder()

	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestOAuthCallback_GitHubGET(t *testing.T) {
	th := newOAuthTestHarness(t)
	th.mockProvider.profile.Provider = "github"

	u := fmt.Sprintf("/auth/oauth/github/callback?code=github-code&state=%s", th.stateToken)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	req.SetPathValue("provider", "github")
	w := httptest.NewRecorder()

	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
}

func TestOAuthCallback_WithQueryAndFormParams(t *testing.T) {
	th := newOAuthTestHarness(t)

	form := url.Values{"code": {"form-code"}, "foo": {"bar"}}
	queryURL := fmt.Sprintf("/auth/oauth/test/callback?state=%s&extra=value", th.stateToken)
	req := httptest.NewRequest(http.MethodPost, queryURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()

	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "window.location.replace") {
		t.Error("expected success response")
	}
}

func TestOAuthCallback_MethodNotAllowed(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		th := newOAuthTestHarness(t)
		state := th.createStateToken(t, "method-"+method)

		u := fmt.Sprintf("/auth/oauth/test/callback?code=auth-code&state=%s", state)
		req := httptest.NewRequest(method, u, nil)
		req.SetPathValue("provider", "test")
		w := httptest.NewRecorder()

		th.callback(w, req)

		res := w.Result()
		checkTestErrors(t).noError(res.Body.Close())

		if res.StatusCode != http.StatusOK {
			t.Errorf("%s: expected 200 through handler, got %d", method, res.StatusCode)
		}
	}
}

func TestOAuthCallback_RouterRegistersBothMethods(t *testing.T) {
	getHarness := newOAuthTestHarness(t)
	postHarness := newOAuthTestHarness(t)

	getState := getHarness.stateToken
	postState := postHarness.stateToken

	mux := http.NewServeMux()
	mux.Handle("GET /auth/oauth/{provider}/callback", http.HandlerFunc(getHarness.oauthHandlers.Callback))
	mux.Handle("POST /auth/oauth/{provider}/callback", http.HandlerFunc(postHarness.oauthHandlers.Callback))

	getURL := fmt.Sprintf("/auth/oauth/test/callback?code=abc&state=%s", getState)
	getReq := httptest.NewRequest(http.MethodGet, getURL, nil)
	getReq.AddCookie(getHarness.oauthHandlers.oauthStateCookie(getState, 600))
	getW := httptest.NewRecorder()
	mux.ServeHTTP(getW, getReq)

	postForm := url.Values{"code": {"abc"}, "state": {postState}}
	postReq := httptest.NewRequest(http.MethodPost, "/auth/oauth/test/callback", strings.NewReader(postForm.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postReq.AddCookie(postHarness.oauthHandlers.oauthStateCookie(postState, 600))
	postW := httptest.NewRecorder()
	mux.ServeHTTP(postW, postReq)

	if getW.Code != http.StatusOK {
		t.Errorf("GET via mux: expected 200, got %d", getW.Code)
	}
	if postW.Code != http.StatusOK {
		t.Errorf("POST via mux: expected 200, got %d", postW.Code)
	}

	putReq := httptest.NewRequest(http.MethodPut, getURL, nil)
	putW := httptest.NewRecorder()
	mux.ServeHTTP(putW, putReq)
	if putW.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT via mux: expected 405, got %d", putW.Code)
	}
}

// TestOAuthCallback_Link_DoesNotTouchSessionCookies guards against B3: a link
// callback must never call writeCookieRedirect, because the linking user
// already has a live session and Callback issues no new tokens for a link —
// falling through would blank the caller's real session cookie with "".
func TestOAuthCallback_Link_DoesNotTouchSessionCookies(t *testing.T) {
	th := newOAuthTestHarness(t)
	checkTestErrors(t).noError(th.userRepo.Create(context.Background(), &domain.User{ID: "user-1", Email: "user1@example.com"}))

	state := th.createLinkStateToken(t, "link-state-value", "user-1")

	u := fmt.Sprintf("/auth/oauth/test/callback?code=auth-code&state=%s", state)
	req := httptest.NewRequest(http.MethodGet, u, nil)
	req.SetPathValue("provider", "test")
	w := httptest.NewRecorder()

	th.callback(w, req)

	res := w.Result()
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if loc != th.baseURL+"/auth/callback" {
		t.Errorf("expected redirect to %s, got %s", th.baseURL+"/auth/callback", loc)
	}

	for _, c := range res.Cookies() {
		if c.Name == "goauth_session" || c.Name == "goauth_refresh" {
			t.Errorf("link callback must not set %s cookie, got value %q", c.Name, c.Value)
		}
	}
}

func mustDecodeJSON(body io.Reader, v any) {
	if err := json.NewDecoder(body).Decode(v); err != nil {
		panic(err)
	}
}
