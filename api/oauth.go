package api

import "time"

// OAuthCallbackResult contains the session or link result of an OAuth callback.
// Callback handles the OAuth callback for both login and link flows.
// OAuthCallbackResult is Callback's outcome. SessionToken/RefreshToken are
// set on a successful login or registration; RequiresVerification and
// VerifyEmail are set instead when the new/existing account still needs
// email verification before a session is issued; a linking callback (state
// token carries a UserID) sets only IsLink and leaves every other field
// zero — the caller already has a valid session from before the link
// started and must not touch it (no new session is created or returned).
type OAuthCallbackResult struct {
	SessionToken         string
	RefreshToken         string
	IsNewUser            bool
	RequiresVerification bool
	VerifyEmail          string
	IsLink               bool
	RequiresTwoFactor    bool      `json:"requiresTwoFactor,omitempty"`
	CodeSent             bool      `json:"codeSent,omitempty"`
	TwoFactorChallenge   string    `json:"challengeId,omitempty"`
	TwoFactorExpiresAt   time.Time `json:"twoFactorExpiresAt,omitempty"`
	bindingToken         string
}

// BindingToken returns the browser binding credential; it is never serialized.
func (r *OAuthCallbackResult) BindingToken() string { return r.bindingToken }

// NewOAuthCallbackResult attaches a binding credential to an OAuth challenge.
func NewOAuthCallbackResult(result OAuthCallbackResult, bindingToken string) *OAuthCallbackResult {
	result.bindingToken = bindingToken
	return &result
}

// OAuthInitiation gives the HTTP layer the authorization URL and the state to
// bind to the initiating browser in an HttpOnly cookie.
type OAuthInitiation struct {
	URL   string
	State string
}
