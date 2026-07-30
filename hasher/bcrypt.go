package hasher

import (
	"crypto/sha256"

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
	preHashed := sha256.Sum256([]byte(password))
	bytes, err := bcrypt.GenerateFromPassword(preHashed[:], h.cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (h *BcryptHasher) Compare(password, hash string) error {
	preHashed := sha256.Sum256([]byte(password))
	return bcrypt.CompareHashAndPassword([]byte(hash), preHashed[:])
}
