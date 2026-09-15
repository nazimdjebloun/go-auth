package keyring

import (
	"bytes"
	"reflect"
	"testing"
)

// FuzzDerive checks the two properties the keyring promises: every subkey is
// the fixed size its consumer expects (32 bytes for AES-256 / HMAC-SHA256),
// and derivation is deterministic — same secret, same keys, on every call and
// every process. Purpose separation is verified too: the password-pepper key
// must never collide with any of the application-subkey material derived from
// the same secret.
func FuzzDerive(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte(""))
	f.Add([]byte("s"))
	f.Add([]byte("correct horse battery staple"))
	f.Add(bytes.Repeat([]byte{0xFF}, 128))
	f.Add([]byte("0123456789abcdef0123456789abcdef"))
	f.Fuzz(func(t *testing.T, secret []byte) {
		k := Derive(secret)
		subkeys := map[string][]byte{
			"CSRF":      k.CSRF,
			"OAuthEnc":  k.OAuthEnc,
			"TwoFactor": k.TwoFactor,
			"OTPPepper": k.OTPPepper,
		}
		for name, key := range subkeys {
			if len(key) != 32 {
				t.Errorf("%s key has length %d, want 32", name, len(key))
			}
		}

		if again := Derive(secret); !reflect.DeepEqual(again, k) {
			t.Errorf("Derive is not deterministic for the same secret")
		}

		passwordPepper := DerivePasswordPepper(secret)
		if bytes.Equal(passwordPepper, k.CSRF) ||
			bytes.Equal(passwordPepper, k.OAuthEnc) ||
			bytes.Equal(passwordPepper, k.TwoFactor) ||
			bytes.Equal(passwordPepper, k.OTPPepper) {
			t.Errorf("password pepper key collides with an application subkey")
		}
	})
}
