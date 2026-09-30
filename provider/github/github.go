// Package github implements GitHub OAuth authentication.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/nazimdjebloun/go-auth/port"
)

var githubEndpoint = oauth2.Endpoint{
	AuthURL:  "https://github.com/login/oauth/authorize",
	TokenURL: "https://github.com/login/oauth/access_" + "token",
}

// Config configures the GitHub OAuth provider.
type Config struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// GitHub exchanges OAuth credentials for GitHub profiles.
type GitHub struct {
	cfg *oauth2.Config
}

// New returns a GitHub OAuth provider.
func New(cfg Config) *GitHub {
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"user:email"}
	}
	return &GitHub{
		cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
			Endpoint:     githubEndpoint,
		},
	}
}

// Name returns the provider name.
func (g *GitHub) Name() string { return "github" }

// OAuth2Config returns the underlying OAuth2 configuration, exposing
// ClientID and ClientSecret for startup validation.
func (g *GitHub) OAuth2Config() *oauth2.Config { return g.cfg }

// AuthURL returns the GitHub authorization URL with PKCE.
func (g *GitHub) AuthURL(state string, codeChallenge string) string {
	return g.cfg.AuthCodeURL(state, oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange exchanges an authorization code for a GitHub profile.
func (g *GitHub) Exchange(ctx context.Context, code string, codeVerifier string) (*port.OAuthProfile, error) {
	token, err := g.cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("github: code exchange failed: %w", err)
	}

	client := g.cfg.Client(ctx, token)

	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("github: failed to fetch user: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("github: user info returned HTTP %d", resp.StatusCode)
	}

	var user struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		Login     string `json:"login"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("github: failed to decode user: %w", err)
	}
	if user.ID <= 0 {
		return nil, fmt.Errorf("github: user info is missing a valid identity")
	}

	email := user.Email
	emailVerified := false
	if email == "" {
		// No public profile email — fall back to /user/emails (requires the
		// user:email scope) and use its explicit per-address verified flag.
		var err error
		email, emailVerified, err = fetchGitHubPrimaryEmail(client)
		if err != nil {
			return nil, err
		}
	} else {
		// GitHub only lets a user choose their public profile email from
		// their set of *verified* addresses (Settings > Emails > Public
		// email) — an unverified address cannot be selected. So a non-empty
		// user.Email is verified by construction; there is no separate
		// "verified" field on /user to check it against, unlike the
		// per-address entries returned by /user/emails above.
		emailVerified = true
	}

	var expiresAt *time.Time
	if !token.Expiry.IsZero() {
		t := token.Expiry
		expiresAt = &t
	}

	name := user.Name
	if name == "" {
		name = user.Login
	}

	return &port.OAuthProfile{
		Provider:       "github",
		ProviderUserID: fmt.Sprintf("%d", user.ID),
		Email:          email,
		EmailVerified:  emailVerified,
		Name:           name,
		AvatarURL:      user.AvatarURL,
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
		TokenExpiresAt: expiresAt,
	}, nil
}

func fetchGitHubPrimaryEmail(client *http.Client) (string, bool, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", false, fmt.Errorf("github: failed to fetch emails: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", false, fmt.Errorf("github: emails returned HTTP %d", resp.StatusCode)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("github: failed to decode emails: %w", err)
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, true, nil
		}
	}
	return "", false, fmt.Errorf("github: no verified primary email found")
}
