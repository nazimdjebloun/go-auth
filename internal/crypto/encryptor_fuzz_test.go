package crypto

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzEncryptorRoundTrip pins the encryption contract: everything that
// Encrypt accepts must come back byte-for-byte identical from Decrypt. Any
// plaintext — empty, multibyte, or pathological — that fails the round trip is
// a ciphertext-format bug, since the cipher itself (AES-256-GCM) is not
// malleable for the holder of the key.
func FuzzEncryptorRoundTrip(f *testing.F) {
	e, err := NewEncryptor(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		"",
		"a",
		"hello world",
		"unicode: 你好世界 Ḉ",
		"nul byte: \x00\x01\x02",
		"long\n" + strings.Repeat("x", 10_000),
		"\xff\xfe\xfd",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, plaintext string) {
		enc, err := e.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", plaintext, err)
		}
		dec, err := e.Decrypt(enc)
		if err != nil {
			t.Fatalf("Decrypt(Encrypt(%q)): %v", plaintext, err)
		}
		if dec != plaintext {
			t.Errorf("round trip mismatch: got %q, want %q", dec, plaintext)
		}
	})
}

// FuzzEncryptorDecrypt feeds arbitrary ciphertext-shaped strings to Decrypt.
// The fail-closed surface is the point: malformed base64, truncated nonce-
// plus-ciphertext, and tag-tampered GCM payloads must all error, and anything
// that does decrypt must be a genuine ciphertext — i.e. it re-encrypts and
// decrypts back to the same plaintext. A successful decrypt of attacker input
// that does not round-trip would signal an authentication bypass.
func FuzzEncryptorDecrypt(f *testing.F) {
	e, err := NewEncryptor(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{
		"",
		"abc",
		"aGVsbG8=",
		"<<<>>>",
		strings.Repeat("A", 200),
		base64.StdEncoding.EncodeToString(make([]byte, 16)),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, encoded string) {
		dec, err := e.Decrypt(encoded)
		if err != nil {
			return
		}
		re, err := e.Encrypt(dec)
		if err != nil {
			t.Fatalf("Encrypt(%q): %v", dec, err)
		}
		dec2, err := e.Decrypt(re)
		if err != nil {
			t.Fatalf("Decrypt of re-encrypted ciphertext: %v", err)
		}
		if dec2 != dec {
			t.Errorf("decrypted value does not round-trip: %q != %q", dec2, dec)
		}
	})
}
