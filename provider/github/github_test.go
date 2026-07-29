package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

type testTransport struct {
	serverURL string
	base      http.RoundTripper
}

func (t *testTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(t.serverURL)
	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host
	return t.base.RoundTrip(req)
}

func TestName(t *testing.T) {
	g := New(Config{})
	if g.Name() != "github" {
		t.Errorf("expected 'github', got %q", g.Name())
	}
}

func TestDefaultScopes(t *testing.T) {
	g := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
	})
	if len(g.cfg.Scopes) != 1 || g.cfg.Scopes[0] != "user:email" {
		t.Errorf("expected [user:email], got %v", g.cfg.Scopes)
	}
}

func TestCustomScopes(t *testing.T) {
	g := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
		Scopes:       []string{"repo", "admin:org"},
	})
	if len(g.cfg.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(g.cfg.Scopes))
	}
	if g.cfg.Scopes[0] != "repo" || g.cfg.Scopes[1] != "admin:org" {
		t.Errorf("unexpected scopes: %v", g.cfg.Scopes)
	}
}

func TestAuthURL(t *testing.T) {
	g := New(Config{
		ClientID:    "test-client",
		RedirectURL: "http://localhost/callback",
	})
	u := g.AuthURL("state123", "challenge456")
	if !strings.Contains(u, "state123") {
		t.Error("AuthURL missing state")
	}
	if !strings.Contains(u, "challenge456") {
		t.Error("AuthURL missing code_challenge")
	}
	if !strings.Contains(u, "S256") {
		t.Error("AuthURL missing code_challenge_method=S256")
	}
}

func TestExchange_Success_WithEmail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "gh-access-token",
				"token_type":    "bearer",
				"refresh_token": "gh-refresh-token",
				"expires_in":    28800,
			})
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":        12345,
				"login":     "testuser",
				"name":      "Test User",
				"email":     "test@example.com",
				"avatar_url": "https://avatars.githubusercontent.com/u/12345",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &testTransport{serverURL: ts.URL, base: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	oldEndpoint := githubEndpoint
	githubEndpoint = oauth2.Endpoint{
		TokenURL: ts.URL + "/login/oauth/access_token",
		AuthURL:  ts.URL + "/login/oauth/authorize",
	}
	defer func() { githubEndpoint = oldEndpoint }()

	g := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
	})

	profile, err := g.Exchange(context.Background(), "auth-code", "verifier")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	if profile.Provider != "github" {
		t.Errorf("expected 'github', got %q", profile.Provider)
	}
	if profile.ProviderUserID != "12345" {
		t.Errorf("expected '12345', got %q", profile.ProviderUserID)
	}
	if profile.Email != "test@example.com" {
		t.Errorf("expected 'test@example.com', got %q", profile.Email)
	}
	if !profile.EmailVerified {
		t.Error("expected email verified")
	}
	if profile.Name != "Test User" {
		t.Errorf("expected 'Test User', got %q", profile.Name)
	}
	if profile.AvatarURL != "https://avatars.githubusercontent.com/u/12345" {
		t.Errorf("unexpected avatar URL: %q", profile.AvatarURL)
	}
	if profile.AccessToken != "gh-access-token" {
		t.Errorf("expected 'gh-access-token', got %q", profile.AccessToken)
	}
	if profile.RefreshToken != "gh-refresh-token" {
		t.Errorf("expected 'gh-refresh-token', got %q", profile.RefreshToken)
	}
	if profile.TokenExpiresAt == nil {
		t.Error("expected non-nil TokenExpiresAt")
	}
}

func TestExchange_Success_EmailFallback(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"token_type":   "bearer",
				"expires_in":   3600,
			})
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":        67890,
				"login":     "nemail-user",
				"name":      "No Email User",
				"email":     "",
				"avatar_url": "https://avatars.githubusercontent.com/u/67890",
			})
		case "/user/emails":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"email": "primary@example.com", "primary": true, "verified": true},
				{"email": "secondary@example.com", "primary": false, "verified": true},
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &testTransport{serverURL: ts.URL, base: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	oldEndpoint := githubEndpoint
	githubEndpoint = oauth2.Endpoint{
		TokenURL: ts.URL + "/login/oauth/access_token",
		AuthURL:  ts.URL + "/login/oauth/authorize",
	}
	defer func() { githubEndpoint = oldEndpoint }()

	g := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
	})

	profile, err := g.Exchange(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	if profile.Email != "primary@example.com" {
		t.Errorf("expected 'primary@example.com', got %q", profile.Email)
	}
	if !profile.EmailVerified {
		t.Error("expected email verified")
	}
	if profile.ProviderUserID != "67890" {
		t.Errorf("expected '67890', got %q", profile.ProviderUserID)
	}
}

func TestExchange_NoVerifiedPrimaryEmail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"token_type":   "bearer",
				"expires_in":   3600,
			})
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":    12345,
				"login": "no-verified",
				"email": "",
			})
		case "/user/emails":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"email": "unverified@example.com", "primary": true, "verified": false},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &testTransport{serverURL: ts.URL, base: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	oldEndpoint := githubEndpoint
	githubEndpoint = oauth2.Endpoint{
		TokenURL: ts.URL + "/login/oauth/access_token",
		AuthURL:  ts.URL + "/login/oauth/authorize",
	}
	defer func() { githubEndpoint = oldEndpoint }()

	g := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
	})

	_, err := g.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected error for no verified primary email, got nil")
	}
}

func TestExchange_TokenError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "bad_verification_code"})
	}))
	defer ts.Close()

	oldEndpoint := githubEndpoint
	githubEndpoint = oauth2.Endpoint{
		TokenURL: ts.URL + "/token",
		AuthURL:  ts.URL + "/auth",
	}
	defer func() { githubEndpoint = oldEndpoint }()

	g := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
	})

	_, err := g.Exchange(context.Background(), "bad-code", "verifier")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestExchange_APIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login/oauth/access_token" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"token_type":   "bearer",
				"expires_in":   3600,
			})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &testTransport{serverURL: ts.URL, base: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	oldEndpoint := githubEndpoint
	githubEndpoint = oauth2.Endpoint{
		TokenURL: ts.URL + "/login/oauth/access_token",
		AuthURL:  ts.URL + "/login/oauth/authorize",
	}
	defer func() { githubEndpoint = oldEndpoint }()

	g := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
	})

	_, err := g.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
