package api

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

// TwoFactorVerifyResult is Verify's outcome — the authenticated user, the
// newly issued session, and the raw tokens that go with it.
type TwoFactorVerifyResult struct {
	User         *domain.User
	Session      *domain.Session
	SessionToken string
	RefreshToken string
}
