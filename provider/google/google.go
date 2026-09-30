// Package google implements Google OAuth authentication.
package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/nazimdjebloun/go-auth/port"
)

// Config configures the Google OAuth provider.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Google exchanges OAuth credentials for Google profiles.
type Google struct {
	cfg *oauth2.Config
}

// New returns a Google OAuth provider.
func New(cfg Config) *Google {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		}
	}
	return &Google{
		cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     google.Endpoint,
		},
	}
}

// Name returns the provider name.
func (g *Google) Name() string { return "google" }

// OAuth2Config returns the underlying OAuth2 configuration, exposing
// ClientID and ClientSecret for startup validation.
func (g *Google) OAuth2Config() *oauth2.Config { return g.cfg }

// AuthURL returns the Google authorization URL with PKCE.
func (g *Google) AuthURL(state string, codeChallenge string) string {
	return g.cfg.AuthCodeURL(state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("prompt", "select_account"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange exchanges an authorization code for a Google profile.
func (g *Google) Exchange(ctx context.Context, code string, codeVerifier string) (*port.OAuthProfile, error) {
	token, err := g.cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("google: code exchange failed: %w", err)
	}

	client := g.cfg.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("google: failed to fetch user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("google: user info returned HTTP %d", resp.StatusCode)
	}

	var user struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		VerifiedEmail bool   `json:"verified_email"`
		Name          string `json:"name"`
		Picture       string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("google: failed to decode user info: %w", err)
	}
	if strings.TrimSpace(user.ID) == "" {
		return nil, fmt.Errorf("google: user info is missing an identity")
	}

	var expiresAt *time.Time
	if !token.Expiry.IsZero() {
		t := token.Expiry
		expiresAt = &t
	}

	return &port.OAuthProfile{
		Provider:       "google",
		ProviderUserID: user.ID,
		Email:          user.Email,
		EmailVerified:  user.VerifiedEmail,
		Name:           user.Name,
		AvatarURL:      user.Picture,
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
		TokenExpiresAt: expiresAt,
	}, nil
}
