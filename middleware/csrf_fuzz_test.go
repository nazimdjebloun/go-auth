package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzVerifyCSRFToken checks the double-submit contract from either side of
// the signature: a token minted over a non-negative nonce with a secret must
// verify under that secret and must fail under any other secret, and an empty
// nonce must be rejected outright (the verifier requires a well-formed
// nonce.signature pair with a non-empty nonce; the generator refuses to mint
// one). The wrong-secret and empty-nonce checks are the load-bearing half — a
// signature produced with different key material is exactly what sibling-
// subdomain cookie injection would supply, and an empty nonce would conflate
// every token issued with an empty secret-derived prefix.
func FuzzVerifyCSRFTokenRoundTrip(f *testing.F) {
	f.Add([]byte("0123456789abcdef0123456789abcdef"), []byte("nonce-data"))
	f.Add([]byte("k"), []byte{})
	f.Add([]byte(""), []byte("s"))
	f.Add([]byte("secret"), []byte("a"))
	f.Fuzz(func(t *testing.T, secret, nonce []byte) {
		if len(secret) == 0 {
			return
		}
		nonceEnc := base64.RawURLEncoding.EncodeToString(nonce)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(nonceEnc))
		sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		token := nonceEnc + "." + sig

		if len(nonce) == 0 {
			if verifyCSRFToken(token, secret) {
				t.Errorf("verifyCSRFToken accepted a token with an empty nonce")
			}
			return
		}

		if !verifyCSRFToken(token, secret) {
			t.Errorf("verifyCSRFToken rejected a token it signed itself (nonce %q)", nonce)
		}

		other := append([]byte(nil), secret...)
		other[0] ^= 0x01
		if verifyCSRFToken(token, other) {
			t.Errorf("verifyCSRFToken accepted a token signed with a different secret")
		}
	})
}

// FuzzGenerateCSRFToken checks the generator's output shape and its fail-closed
// behavior on an invalid requested length. Real configs normalize lengths, but
// the generator is reachable with any int during wiring and tests; requesting a
// negative or zero length must be an error, never a panic and never an
// unverifiable token.
func FuzzGenerateCSRFToken(f *testing.F) {
	f.Add(32, []byte("0123456789abcdef0123456789abcdef"))
	f.Add(1, []byte("s"))
	f.Add(0, []byte("s"))
	f.Add(-1, []byte("s"))
	f.Add(64, []byte(""))
	f.Fuzz(func(t *testing.T, length int, secret []byte) {
		if len(secret) == 0 {
			return
		}
		if length < 1 {
			if _, err := generateCSRFToken(length, secret); err == nil {
				t.Errorf("generateCSRFToken(%d) succeeded, want error", length)
			}
			return
		}
		if length > 4096 {
			return // defensive; allocation per iteration aside, 4096 covers the realistic surface
		}
		token, err := generateCSRFToken(length, secret)
		if err != nil {
			t.Fatalf("generateCSRFToken(%d): %v", length, err)
		}
		parts := strings.Split(token, ".")
		if len(parts) != 2 {
			t.Fatalf("token %q is not nonce.signature", token)
		}
		nonce, derr := base64.RawURLEncoding.DecodeString(parts[0])
		if derr != nil {
			t.Fatalf("nonce %q is not base64url: %v", parts[0], derr)
		}
		if len(nonce) != length {
			t.Errorf("nonce has %d bytes, want %d", len(nonce), length)
		}
		if !verifyCSRFToken(token, secret) {
			t.Errorf("generated token %q does not verify", token)
		}
	})
}
