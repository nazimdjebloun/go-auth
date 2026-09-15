package service

import (
	"encoding/hex"
	"strings"
	"testing"
)

func FuzzHashToken(f *testing.F) {
	f.Add("")
	f.Add("hello")
	f.Add(strings.Repeat("a", 1000))
	f.Add("token with spaces")
	f.Add("unicode: 你好世界")
	f.Add("special: !@#$%^&*()")
	f.Fuzz(func(t *testing.T, token string) {
		h := hashToken(token)
		if len(h) != 64 {
			t.Errorf("hashToken output has %d chars, want 64 hex chars", len(h))
		}
		if _, err := hex.DecodeString(h); err != nil {
			t.Errorf("hashToken output is not valid hex: %q", h)
		}
		// Deterministic: same input → same output.
		h2 := hashToken(token)
		if h != h2 {
			t.Errorf("hashToken is not deterministic: %q != %q", h, h2)
		}
	})
}

func FuzzHashOTP(f *testing.F) {
	f.Add("", []byte("pepper"))
	f.Add("123456", []byte("pepper"))
	f.Add("abcdef", []byte("long-pepper-value"))
	f.Add(strings.Repeat("x", 256), []byte("key"))
	f.Fuzz(func(t *testing.T, code string, pepper []byte) {
		if len(pepper) == 0 || len(code) == 0 {
			return
		}
		h := hashOTP(code, pepper)
		if len(h) != 64 {
			t.Errorf("hashOTP output has %d chars, want 64 hex chars", len(h))
		}
		if _, err := hex.DecodeString(h); err != nil {
			t.Errorf("hashOTP output is not valid hex: %q", h)
		}
		// Round-trip: hashOTP → verifyOTP should succeed.
		if !verifyOTP(code, h, pepper) {
			t.Errorf("verifyOTP failed on hashOTP output for code=%q", code)
		}
	})
}

func FuzzVerifyOTP(f *testing.F) {
	f.Add("123456", []byte("pepper"))
	f.Add("codes", []byte("key"))
	f.Fuzz(func(t *testing.T, code string, pepper []byte) {
		if len(pepper) == 0 || len(code) == 0 {
			return
		}
		h := hashOTP(code, pepper)
		if !verifyOTP(code, h, pepper) {
			t.Errorf("verifyOTP failed on its own hashOTP output")
		}
		// Wrong code must not verify.
		wrong := code + "x"
		if verifyOTP(wrong, h, pepper) {
			t.Errorf("verifyOTP succeeded with wrong code")
		}
	})
}

func FuzzHashFormatPrefix(f *testing.F) {
	f.Add("")
	f.Add("$2a$12$N9qo8uLOickgx2ZMRZoMye")
	f.Add("$argon2id$v=19$m=65536,t=3,p=4$")
	f.Add("pbkdf2_sha256$150000$")
	f.Add("barevalue")
	f.Add("$")
	f.Add("$$")
	f.Fuzz(func(t *testing.T, hash string) {
		prefix := hashFormatPrefix(hash)
		if prefix == "" && hash != "" {
			// Empty prefix is only valid for empty input.
			return
		}
		if len(prefix) > len(hash) {
			t.Errorf("prefix %q is longer than input %q", prefix, hash)
		}
	})
}
