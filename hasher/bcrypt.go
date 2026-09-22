// Package hasher provides the default password hasher: bcrypt. The optional
// Argon2id implementation lives in hasher/argon2id, and hasher/registry
// verifies existing hashes by their algorithm prefix so swapping hashers never
// invalidates stored passwords. See port.Hasher for the contract.
package hasher

import (
	"golang.org/x/crypto/bcrypt"
)

type BcryptHasher struct {
	cost int
}

func New(cost int) *BcryptHasher {
	if cost < bcrypt.MinCost {
		cost = bcrypt.DefaultCost
	}
	return &BcryptHasher{cost: cost}
}

func (h *BcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (h *BcryptHasher) Compare(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
