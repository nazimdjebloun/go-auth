package api

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// AuthStep is the next frontend action after a successful authentication flow.
// It does not replace server-side authorization or an HTTP error response.
type AuthStep string

// Authentication steps have the same meaning in JSON and OAuth callbacks.
const (
	StepAuthenticated     AuthStep = "authenticated"
	StepVerifyEmail       AuthStep = "verify_email"
	StepTwoFactor         AuthStep = "two_factor"
	StepVerifyInviteEmail AuthStep = "verify_invite_email"
	StepSignIn            AuthStep = "sign_in"
	StepLinked            AuthStep = "linked"
)

// AuthenticationResponse is the credential-free HTTP authentication outcome.
// Session credentials and browser proofs travel only through the existing HttpOnly cookies.
// ChallengeID identifies a challenge; it is not sufficient to redeem one.
type AuthenticationResponse struct {
	Step                 AuthStep             `json:"step"`
	User                 *domain.User         `json:"user,omitempty"`
	Session              *domain.Session      `json:"session,omitempty"`
	ChallengeID          string               `json:"challengeId,omitempty"`
	ExpiresAt            *time.Time           `json:"expiresAt,omitempty"`
	CodeSent             *bool                `json:"codeSent,omitempty"`
	IsNewUser            bool                 `json:"isNewUser,omitempty"`
	Message              string               `json:"message,omitempty"`
	VerificationDelivery VerificationDelivery `json:"verificationDelivery,omitempty"`
}
