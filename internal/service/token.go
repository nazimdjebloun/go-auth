package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// hashOTP peppers a low-entropy code/OTP with HMAC-SHA256 before storage.
// The pepper is keyring's OTPPepper subkey ("goauth-otp-pepper-v1"), never the
// raw app secret and never shared with any other purpose. The hex encoding
// keeps the TEXT token_hash column unchanged; verification must decode back
// to bytes and use hmac.Equal (see verifyOTP), never == on the hex strings.
//
// High-entropy tokens (32-byte crypto/rand session, reset, invite, OAuth
// state) stay on hashToken above — HMAC is for short codes only.
func hashOTP(code string, pepper []byte) string {
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(code))
	return hex.EncodeToString(mac.Sum(nil))
}

// stalePepper reports whether a stored low-entropy code predates the live OTP
// pepper, i.e. it was hashed under a pepper that is gone and can never verify
// again. Either timestamp being zero (hand-built configs, legacy rows without
// a created_at) means "unknown" and returns false — the caller falls through
// to the normal HMAC comparison rather than expiring something it cannot
// judge. Callers must return an expired-style error on true WITHOUT running
// the HMAC comparison (the outcome is unknowable either way) and WITHOUT
// touching any attempt/rate-limit counter (the user did nothing wrong).
func stalePepper(issuedAt, pepperRotatedAt time.Time) bool {
	if issuedAt.IsZero() || pepperRotatedAt.IsZero() {
		return false
	}
	return issuedAt.Before(pepperRotatedAt)
}

// verifyOTP recomputes the HMAC of a supplied low-entropy code and compares
// it to the stored hex-encoded MAC in constant time. It fails closed on an
// empty pepper or a malformed stored value. Callers must fetch the candidate
// row by ID (or by user+type) first and compare here in app code — never rely
// on a SQL `=` lookup over the MAC as the comparison, and never route this
// through hasher.Compare/bcrypt (slow-hash on an unauthenticated endpoint is
// a DoS amplifier; HMAC + attempt cap + short TTL is the correct primitive).
func verifyOTP(code, storedHex string, pepper []byte) bool {
	if len(pepper) == 0 {
		return false
	}
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(code))
	want, err := hex.DecodeString(storedHex)
	if err != nil {
		return false
	}
	return hmac.Equal(mac.Sum(nil), want)
}
