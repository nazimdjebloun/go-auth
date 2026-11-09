package api

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// ChangeNameInput updates the profile of the authenticated user.
type ChangeNameInput struct {
	UserID string `json:"-"`
	Name   string `json:"name"`
}

// DeleteAccountInput authenticates a password-based account deletion.
type DeleteAccountInput struct {
	UserID   string `json:"-"`
	Password string `json:"password"`
}

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

// BindingToken returns the proof the transport preserves for the initiating
// client. Browser handlers set it as a cookie. It is not serialized.
func (r *LoginResult) BindingToken() string { return r.bindingToken }

// RegisterInput contains values used to register a user.
type RegisterInput struct {
	Email     string
	Password  string
	Name      string
	IP        string
	UserAgent string
}

// RegisterResult is the transport-neutral registration result. The HTTP layer
// translates it into AuthenticationResponse and sets credentials as cookies.
type RegisterResult struct {
	User                 *domain.User    `json:"user"`
	Session              *domain.Session `json:"session,omitempty"`
	SessionToken         string          `json:"sessionToken,omitempty"`
	RefreshToken         string          `json:"refreshToken,omitempty"`
	RequiresVerification bool            `json:"requiresVerification,omitempty"`
	// VerificationDelivery is set only when email verification is required.
	// A failed attempt does not undo the committed account or issue a session.
	VerificationDelivery VerificationDelivery `json:"verificationDelivery,omitempty"`

	RequiresTwoFactor  bool      `json:"requiresTwoFactor,omitempty"`
	CodeSent           bool      `json:"codeSent,omitempty"`
	TwoFactorChallenge string    `json:"challengeId,omitempty"`
	TwoFactorExpiresAt time.Time `json:"twoFactorExpiresAt,omitempty"`

	// bindingToken is deliberately unexported so JSON cannot expose it beside
	// the challenge ID. Browser handlers use a binding cookie; nonbrowser
	// transports preserve the proof in protected per-client flow storage.
	bindingToken string
}

// BindingToken returns the client-binding proof, not serialized into JSON.
// See the field comment for browser and nonbrowser transport handling.
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
