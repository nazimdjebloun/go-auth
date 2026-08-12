package service

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
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

type CompleteInviteInput struct {
	Code            string
	Name            string
	Password        string
	ConfirmPassword string
	IP              string
	UserAgent       string
}

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

type ForgotPasswordInput struct {
	Email string
}

type ResetPasswordInput struct {
	Code        string
	NewPassword string
}

type ChangePasswordInput struct {
	UserID          string
	OldPassword     string
	NewPassword     string
	ExceptSessionID string
}

type ConfirmSetPasswordInput struct {
	UserID      string
	Code        string
	NewPassword string
}

type ListSessionsResult struct {
	Sessions []domain.Session
}

type AdminListUsersInput struct {
	Offset         int
	Limit          int // default 20, max 100
	Email          *string
	Role           *domain.Role
	Search         *string
	OrderBy        string // "created_at" or "updated_at"
	OrderDirection string // "asc" or "desc"
}

type AdminListUsersResult struct {
	Users  []domain.User `json:"users"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit,omitempty"`
	Offset int           `json:"offset,omitempty"`
}

type ListInvitesInput struct {
	Offset int
	Limit  int
	Search string
	Status string
}

type CreateInviteInput struct {
	Email   string
	AdminID string
}

type EmailData struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

type CreateUserInput struct {
	Email    string
	Password string
	Name     string
	Role     string
}

type AdminListUserSessionsInput struct {
	UserID string
	Offset int
	Limit  int
}

type ConfirmDeleteAccountInput struct {
	UserID string
	Code   string
}
