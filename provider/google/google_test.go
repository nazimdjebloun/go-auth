package google

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
	if g.Name() != "google" {
		t.Errorf("expected 'google', got %q", g.Name())
	}
}

func TestDefaultScopes(t *testing.T) {
	g := New(Config{
		ClientID:    "test-client",
		ClientSecret: "test-secret",
		RedirectURL: "http://localhost/callback",
	})
	if len(g.cfg.Scopes) != 2 {
		t.Fatalf("expected 2 default scopes, got %d", len(g.cfg.Scopes))
	}
	if g.cfg.Scopes[0] != "https://www.googleapis.com/auth/userinfo.email" {
		t.Errorf("unexpected scope: %q", g.cfg.Scopes[0])
	}
	if g.cfg.Scopes[1] != "https://www.googleapis.com/auth/userinfo.profile" {
		t.Errorf("unexpected scope: %q", g.cfg.Scopes[1])
	}
}

func TestCustomScopes(t *testing.T) {
	g := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
		Scopes:       []string{"custom-scope"},
	})
	if len(g.cfg.Scopes) != 1 || g.cfg.Scopes[0] != "custom-scope" {
		t.Errorf("expected [custom-scope], got %v", g.cfg.Scopes)
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
	if !strings.Contains(u, "select_account") {
		t.Error("AuthURL missing prompt=select_account")
	}
}

func TestExchange_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token":  "access-token-123",
				"token_type":    "Bearer",
				"refresh_token": "refresh-token-456",
				"expires_in":    3600,
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":             "google-user-1",
			"email":          "test@gmail.com",
			"verified_email": true,
			"name":           "Test User",
			"picture":        "https://example.com/avatar.jpg",
		})
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &testTransport{serverURL: ts.URL, base: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	g := &Google{
		cfg: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Scopes:       []string{"email", "profile"},
			Endpoint: oauth2.Endpoint{
				TokenURL: ts.URL + "/token",
				AuthURL:  ts.URL + "/auth",
			},
		},
	}

	profile, err := g.Exchange(context.Background(), "auth-code", "verifier")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}

	if profile.Provider != "google" {
		t.Errorf("expected 'google', got %q", profile.Provider)
	}
	if profile.ProviderUserID != "google-user-1" {
		t.Errorf("expected 'google-user-1', got %q", profile.ProviderUserID)
	}
	if profile.Email != "test@gmail.com" {
		t.Errorf("expected 'test@gmail.com', got %q", profile.Email)
	}
	if !profile.EmailVerified {
		t.Error("expected email verified")
	}
	if profile.Name != "Test User" {
		t.Errorf("expected 'Test User', got %q", profile.Name)
	}
	if profile.AvatarURL != "https://example.com/avatar.jpg" {
		t.Errorf("expected avatar URL, got %q", profile.AvatarURL)
	}
	if profile.AccessToken != "access-token-123" {
		t.Errorf("expected 'access-token-123', got %q", profile.AccessToken)
	}
	if profile.RefreshToken != "refresh-token-456" {
		t.Errorf("expected 'refresh-token-456', got %q", profile.RefreshToken)
	}
	if profile.TokenExpiresAt == nil {
		t.Error("expected non-nil TokenExpiresAt")
	}
}

func TestExchange_NoExpiry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "no-expiry-token",
				"token_type":   "Bearer",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":    "user-2",
			"email": "test2@gmail.com",
		})
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &testTransport{serverURL: ts.URL, base: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	g := &Google{
		cfg: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL: ts.URL + "/token",
				AuthURL:  ts.URL + "/auth",
			},
		},
	}

	profile, err := g.Exchange(context.Background(), "code", "verifier")
	if err != nil {
		t.Fatalf("Exchange failed: %v", err)
	}
	if profile.TokenExpiresAt != nil {
		t.Error("expected nil TokenExpiresAt for no-expiry token")
	}
}

func TestExchange_TokenError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
	}))
	defer ts.Close()

	g := &Google{
		cfg: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL: ts.URL + "/token",
				AuthURL:  ts.URL + "/auth",
			},
		},
	}

	_, err := g.Exchange(context.Background(), "bad-code", "verifier")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestExchange_APIError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	origTransport := http.DefaultTransport
	http.DefaultTransport = &testTransport{serverURL: ts.URL, base: origTransport}
	defer func() { http.DefaultTransport = origTransport }()

	g := &Google{
		cfg: &oauth2.Config{
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost/callback",
			Endpoint: oauth2.Endpoint{
				TokenURL: ts.URL + "/token",
				AuthURL:  ts.URL + "/auth",
			},
		},
	}

	_, err := g.Exchange(context.Background(), "code", "verifier")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
