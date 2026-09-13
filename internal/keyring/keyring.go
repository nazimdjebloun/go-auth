package keyring

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

type Keys struct {
	CSRF      []byte
	OAuthEnc  []byte
	TwoFactor []byte
	OTPPepper []byte
}

// Derive is pure: the same secret always yields the same keys, on every
// instance and every boot. It deliberately stamps no timestamps — a
// wall-clock-at-boot rotation marker here would disagree across instances
// during a rolling deploy (see SecurityConfig.PepperRotatedAt, which is
// operator-set precisely so every instance shares one value).
func Derive(secret []byte) Keys {
	return Keys{
		CSRF:      deriveKey(secret, []byte("goauth-csrf-signing-v1")),
		OAuthEnc:  deriveKey(secret, []byte("goauth-oauth-encryption-v1")),
		TwoFactor: deriveKey(secret, []byte("goauth-2fa-binding-v1")),
		OTPPepper: deriveKey(secret, []byte("goauth-otp-pepper-v1")),
	}
}

// DerivePasswordPepper derives the HMAC key used by the optional password
// pepper feature. Its input is independent from the application secret used
// by Derive, so rotating WithSecret does not invalidate password hashes.
func DerivePasswordPepper(secret []byte) []byte {
	return deriveKey(secret, []byte("goauth-password-pepper-v1"))
}

func deriveKey(secret, info []byte) []byte {
	h := hkdf.New(sha256.New, secret, []byte("goauth-v1"), info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(h, key); err != nil {
		panic("goauth: hkdf key derivation failed: " + err.Error())
	}
	return key
}
