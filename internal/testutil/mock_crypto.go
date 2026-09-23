// Package testutil provides in-memory test doubles shared across packages.
package testutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/nazimdjebloun/go-auth/domain"
)

// MockHasher provides deterministic password hashing for tests.
type MockHasher struct{}

// Hash returns the SHA-256 digest of password.
func (m *MockHasher) Hash(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]), nil
}

// Compare checks password against a digest returned by Hash.
func (m *MockHasher) Compare(password, hash string) error {
	sum := sha256.Sum256([]byte(password))
	if hex.EncodeToString(sum[:]) != hash {
		return domain.ErrInvalidCredentials
	}
	return nil
}

// ─── mockTokenGen ───────────────────────────────────────────────────

// MockTokenGen creates random test tokens with a configurable byte length.
type MockTokenGen struct {
	Length int
}

// Generate returns a random hexadecimal token.
func (m *MockTokenGen) Generate() (string, error) {
	b := make([]byte, m.Length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
