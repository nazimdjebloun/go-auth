package api

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// LoginInput contains user login credentials.
type LoginInput struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
}

// LoginResult contains either a session or the next authentication challenge.
type LoginResult struct {
	User                 *domain.User    `json:"user"`
	Session              *domain.Session `json:"session,omitempty"`
	SessionToken         string          `json:"sessionToken,omitempty"`
	RefreshToken         string          `json:"refreshToken,omitempty"`
	RequiresVerification bool            `json:"requiresVerification,omitempty"`

	RequiresTwoFactor  bool      `json:"requiresTwoFactor,omitempty"`
	CodeSent           bool      `json:"codeSent,omitempty"`
	TwoFactorChallenge string    `json:"challengeId,omitempty"`
	TwoFactorExpiresAt time.Time `json:"twoFactorExpiresAt,omitempty"`

	bindingToken string // see RegisterResult.bindingToken
}

// BindingToken returns the challenge binding token for the handler to set as a
// cookie. Not serialized — see RegisterResult.bindingToken.
func (r *LoginResult) BindingToken() string { return r.bindingToken }

// RegisterInput contains values used to register a user.
type RegisterInput struct {
	Email     string
	Password  string
	Name      string
	IP        string
	UserAgent string
}

// RegisterResult is serialized directly by the HTTP handler on the normal
// success path. Tags keep it consistent with the hand-built map the handler
// uses on the requires-verification path ({"user", "requiresVerification",
// "message"}) — both used to produce the same field capitalized differently
// depending on which branch ran.
type RegisterResult struct {
	User                 *domain.User    `json:"user"`
	Session              *domain.Session `json:"session,omitempty"`
	SessionToken         string          `json:"sessionToken,omitempty"`
	RefreshToken         string          `json:"refreshToken,omitempty"`
	RequiresVerification bool            `json:"requiresVerification,omitempty"`

	RequiresTwoFactor  bool      `json:"requiresTwoFactor,omitempty"`
	CodeSent           bool      `json:"codeSent,omitempty"`
	TwoFactorChallenge string    `json:"challengeId,omitempty"`
	TwoFactorExpiresAt time.Time `json:"twoFactorExpiresAt,omitempty"`

	// bindingToken is deliberately unexported: it must reach the client as a
	// cookie set by the handler, never as a field in the JSON body, or it
	// would leak alongside the challenge id it is meant to be separate from.
	bindingToken string
}

// BindingToken returns the challenge binding token for the handler to set as a
// cookie. Not serialized — see the field comment.
func (r *RegisterResult) BindingToken() string { return r.bindingToken }

// NewRegisterResult attaches the challenge binding token without serializing it.
func NewRegisterResult(result RegisterResult, bindingToken string) *RegisterResult {
	result.bindingToken = bindingToken
	return &result
}

// NewLoginResult attaches the challenge binding token without serializing it.
func NewLoginResult(result LoginResult, bindingToken string) *LoginResult {
	result.bindingToken = bindingToken
	return &result
}
