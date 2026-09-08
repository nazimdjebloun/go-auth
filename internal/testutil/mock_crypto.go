package testutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/nazimdjebloun/go-auth/domain"
)

type MockHasher struct{}

func (m *MockHasher) Hash(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]), nil
}

func (m *MockHasher) Compare(password, hash string) error {
	sum := sha256.Sum256([]byte(password))
	if hex.EncodeToString(sum[:]) != hash {
		return domain.ErrInvalidCredentials
	}
	return nil
}

// ─── mockTokenGen ───────────────────────────────────────────────────

type MockTokenGen struct {
	Length int
}

func (m *MockTokenGen) Generate() (string, error) {
	b := make([]byte, m.Length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
