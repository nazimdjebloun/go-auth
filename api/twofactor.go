package api

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// TwoFactorVerifyInput completes a challenge using the code and browser binding.
// BindingToken comes from the binding cookie, never from the request body.
type TwoFactorVerifyInput struct {
	ChallengeID  string `json:"challengeId"`
	BindingToken string `json:"-"`
	Code         string `json:"code"`
	IP           string `json:"-"`
	UserAgent    string `json:"-"`
}

// TwoFactorResendInput identifies a challenge bound to the requesting browser.
type TwoFactorResendInput struct {
	ChallengeID  string `json:"challengeId"`
	BindingToken string `json:"-"`
}

// TwoFactorEnableInput enables two-factor authentication for the authenticated user.
// UserID and CallerSessionID come from the validated session. With CallerSessionID
// supplied, the zero value of KeepOtherSessions revokes the user's other sessions.
type TwoFactorEnableInput struct {
	UserID            string `json:"-"`
	Password          string `json:"password"`
	KeepOtherSessions bool   `json:"keepOtherSessions"`
	CallerSessionID   string `json:"-"`
}

// TwoFactorDisableInput authenticates disabling the user's two-factor setting.
type TwoFactorDisableInput struct {
	UserID   string `json:"-"`
	Password string `json:"password"`
}

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

// TwoFactorVerifyResult is Verify's outcome — the authenticated user, the
// newly issued session, and the raw tokens that go with it.
type TwoFactorVerifyResult struct {
	User         *domain.User
	Session      *domain.Session
	SessionToken string
	RefreshToken string
}
