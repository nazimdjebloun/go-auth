package service

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// ChallengeResult describes a pending 2FA challenge.
//
// Sent is false when an existing, still-usable challenge was reused rather than
// a new code mailed — the caller gets the same ID back and no second email.
// BindingToken is the HMAC that ties the challenge to the client that started
// it; it is empty when challenge binding is disabled.
type ChallengeResult struct {
	ID           string
	Sent         bool
	ExpiresAt    time.Time
	BindingToken string
}

// VerificationResult describes the outcome of a verification-email send.
//
// Sent is false when a still-usable code already existed and was left in place
// rather than a second one mailed — the same "reused, not resent" outcome
// ChallengeResult.Sent reports for 2FA, and reported the same way for the same
// reason: a deliberate skip and a dead mailer are indistinguishable to a caller
// that only sees a nil error, which makes a broken SMTP config look like a
// working one. ExpiresAt is the live code's expiry, whether it was just minted
// or reused.
type VerificationResult struct {
	Sent      bool
	ExpiresAt time.Time
}

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

// LoginInput contains user login credentials.
type LoginInput struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
}

// LoginResult has the same dual-shape rationale as RegisterResult above.
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

// CompleteInviteInput contains values used to register from an invitation.
type CompleteInviteInput struct {
	Code            string
	Name            string
	Password        string
	ConfirmPassword string
	IP              string
	UserAgent       string
}

// CompleteInviteResult contains the registered user and session.
type CompleteInviteResult struct {
	User         *domain.User    `json:"user"`
	Session      *domain.Session `json:"session,omitempty"`
	SessionToken string          `json:"sessionToken,omitempty"`
	RefreshToken string          `json:"refreshToken,omitempty"`

	RequiresTwoFactor  bool      `json:"requiresTwoFactor,omitempty"`
	CodeSent           bool      `json:"codeSent,omitempty"`
	TwoFactorChallenge string    `json:"challengeId,omitempty"`
	TwoFactorExpiresAt time.Time `json:"twoFactorExpiresAt,omitempty"`

	bindingToken string // see RegisterResult.bindingToken
}

// BindingToken returns the challenge binding token for the handler to set as a
// cookie. Not serialized — see RegisterResult.bindingToken.
func (r *CompleteInviteResult) BindingToken() string { return r.bindingToken }

// ForgotPasswordInput identifies the account requesting a password reset.
type ForgotPasswordInput struct {
	Email string
}

// ResetPasswordInput contains a reset code and new password.
type ResetPasswordInput struct {
	Code        string
	NewPassword string
}

// ChangePasswordInput contains a user's current and new passwords.
type ChangePasswordInput struct {
	UserID          string
	OldPassword     string
	NewPassword     string
	ExceptSessionID string
}

// ConfirmSetPasswordInput contains a setup code and new password.
type ConfirmSetPasswordInput struct {
	UserID      string
	Code        string
	NewPassword string
}

// ListSessionsResult contains sessions and the matching total.
type ListSessionsResult struct {
	Sessions []domain.Session
}

// AdminListUsersInput contains administrator user filters.
type AdminListUsersInput struct {
	ActorID          string // the admin performing this call
	Offset           int
	Limit            int // default 20, max 100
	Email            *string
	Role             *domain.Role
	IsBanned         *bool
	IsVerified       *bool
	TwoFactorEnabled *bool
	// NeverLoggedIn and LastLoginBefore are independent dormancy filters —
	// see port.UserFilter's doc comment for why they're kept separate.
	NeverLoggedIn   *bool
	LastLoginBefore *time.Time
	Search          *string
	OrderBy         port.UserSortField
	OrderDirection  port.SortDirection
}

// AdminListUsersResult contains users and the matching total.
type AdminListUsersResult struct {
	Users  []domain.User `json:"users"`
	Limit  int           `json:"limit,omitempty"`
	Offset int           `json:"offset,omitempty"`
}

// ListInvitesInput contains account invitation filters.
type ListInvitesInput struct {
	ActorID        string
	Offset         int
	Limit          int
	Search         string
	Status         string
	OrderBy        port.InviteSortField
	OrderDirection port.SortDirection
}

// CreateInviteInput contains values used to create an account invitation.
type CreateInviteInput struct {
	Email   string
	AdminID string
}

// EmailData contains values used to render an email.
type EmailData struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

// CreateUserInput contains values used to create a user.
type CreateUserInput struct {
	ActorID  string // the admin performing this call
	Email    string
	Password string
	Name     string
	Role     string
}

// AdminListUserSessionsInput contains pagination for a user's sessions.
type AdminListUserSessionsInput struct {
	ActorID string // the admin performing this call
	UserID  string
	Offset  int
	Limit   int
}

// ConfirmDeleteAccountInput contains an account-deletion code.
type ConfirmDeleteAccountInput struct {
	UserID string
	Code   string
}
