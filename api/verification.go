package api

import (
	"time"
)

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
