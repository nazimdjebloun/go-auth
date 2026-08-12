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
}

func Derive(secret []byte) Keys {
	return Keys{
		CSRF:      deriveKey(secret, []byte("goauth-csrf-signing-v1")),
		OAuthEnc:  deriveKey(secret, []byte("goauth-oauth-encryption-v1")),
		TwoFactor: deriveKey(secret, []byte("goauth-2fa-binding-v1")),
	}
}

func deriveKey(secret, info []byte) []byte {
	h := hkdf.New(sha256.New, secret, []byte("goauth-v1"), info)
	key := make([]byte, 32)
	io.ReadFull(h, key)
	return key
}
