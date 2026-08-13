package crypto

import (
	"encoding/base64"
	"testing"
)

func newTestEncryptor(t *testing.T) *Encryptor {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	e, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	return e
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	e := newTestEncryptor(t)
	plaintext := "the quick brown fox jumps over the lazy dog"

	ct, err := e.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := e.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != plaintext {
		t.Errorf("round trip mismatch: got %q, want %q", pt, plaintext)
	}
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	e := newTestEncryptor(t)
	ct, err := e.Encrypt("")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	pt, err := e.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if pt != "" {
		t.Errorf("expected empty string round trip, got %q", pt)
	}
}

func TestEncrypt_NonceUniqueness(t *testing.T) {
	e := newTestEncryptor(t)
	plaintext := "same plaintext every time"

	seen := make(map[string]bool)
	const n = 20
	for i := 0; i < n; i++ {
		ct, err := e.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if seen[ct] {
			t.Fatalf("ciphertext repeated across calls — nonce reuse: %q", ct)
		}
		seen[ct] = true
	}
	if len(seen) != n {
		t.Errorf("expected %d distinct ciphertexts, got %d", n, len(seen))
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	e := newTestEncryptor(t)
	ct, err := e.Encrypt("sensitive token value")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	data, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("failed to decode test ciphertext: %v", err)
	}
	// Flip the last byte, which lands in the GCM auth tag (nonce is 12
	// bytes, prepended), so this corrupts integrity, not just the nonce.
	data[len(data)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(data)

	if _, err := e.Decrypt(tampered); err == nil {
		t.Error("expected Decrypt to reject a tampered ciphertext, got nil error")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	e := newTestEncryptor(t)
	if _, err := e.Decrypt("not valid base64!!!"); err == nil {
		t.Error("expected error for invalid base64 input")
	}
}

func TestDecrypt_TruncatedCiphertext(t *testing.T) {
	e := newTestEncryptor(t)
	// Shorter than a GCM nonce (12 bytes) once decoded.
	short := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := e.Decrypt(short); err == nil {
		t.Error("expected error for ciphertext shorter than the nonce")
	}
}

func TestNewEncryptor_RejectsShortKey(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		if _, err := NewEncryptor(make([]byte, n)); err == nil {
			t.Errorf("expected NewEncryptor to reject a %d-byte key", n)
		}
	}
}

func TestNewEncryptor_Accepts32ByteKey(t *testing.T) {
	if _, err := NewEncryptor(make([]byte, 32)); err != nil {
		t.Errorf("expected a 32-byte key to be accepted, got %v", err)
	}
}

func TestEncrypt_DifferentKeysProduceIncompatibleCiphertext(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i + 1)
	}
	e1, _ := NewEncryptor(key1)
	e2, _ := NewEncryptor(key2)

	ct1, err := e1.Encrypt("shared plaintext")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := e2.Decrypt(ct1); err == nil {
		t.Error("expected decryption under a different key to fail")
	}
}
