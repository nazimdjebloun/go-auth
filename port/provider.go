package port

import (
	"context"
	"time"
)

// OAuthProfile is the identity OAuthProvider.Exchange resolves from the
// provider's own userinfo endpoint after a successful code exchange.
type OAuthProfile struct {
	Provider       string
	ProviderUserID string // the provider's own opaque user ID — never the email, which can change
	Email          string
	// EmailVerified must reflect the provider's own verification claim, not
	// an assumption that OAuth implies a verified email. go-auth trusts this
	// value when deciding whether to skip its own verification step — if a
	// provider doesn't expose this, treat it as false and let
	// RequireEmailVerification (if enabled) send its own code.
	EmailVerified  bool
	Name           string
	AvatarURL      string
	AccessToken    string
	RefreshToken   string
	TokenExpiresAt *time.Time
	Raw            map[string]any
}

// OAuthProvider is what WithProvider registers. go-auth ships GitHub and
// Google implementations (provider/github, provider/google) — implement
// this against any other OAuth2 provider's authorization and token
// endpoints to add one. See docs/providers/custom.mdx for a worked example.
//
// PKCE (RFC 7636, S256) is mandatory for every provider registered this way
// — go-auth generates and stores the code verifier itself and passes it to
// Exchange, regardless of whether the target provider strictly requires
// PKCE. AuthURL and Exchange must round-trip it faithfully rather than
// implementing their own alternative.
type OAuthProvider interface {
	// Name identifies the provider in URLs (/auth/oauth/{name}/...) and
	// stored provider_accounts rows. Must be non-empty and unique among all
	// registered providers — New() rejects duplicates and empty names.
	Name() string

	// AuthURL builds the URL to redirect the browser to. state is an opaque,
	// single-use anti-CSRF token go-auth generates and expects back
	// unmodified on the callback (as the standard OAuth2 "state" parameter).
	// codeChallenge is the PKCE S256 challenge derived from the verifier
	// go-auth generated for this attempt — pass it through as the
	// "code_challenge" parameter with "code_challenge_method=S256".
	AuthURL(state string, codeChallenge string) string

	// Exchange trades the authorization code from the callback for the
	// user's profile. codeVerifier is the PKCE verifier matching the
	// challenge AuthURL sent — pass it as the token endpoint's
	// "code_verifier" parameter. Return a non-nil error for any failure
	// (bad code, provider outage, malformed userinfo response); go-auth
	// surfaces it to the caller as a generic provider_error, never the raw
	// message, so it's safe to wrap provider-specific details here for logs.
	Exchange(ctx context.Context, code string, codeVerifier string) (*OAuthProfile, error)
}
