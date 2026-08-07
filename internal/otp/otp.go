package otp

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

const Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func Generate(length int) (string, error) {
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(Alphabet))))
		if err != nil {
			return "", fmt.Errorf("otp generate: %w", err)
		}
		b[i] = Alphabet[n.Int64()]
	}
	return string(b), nil
}
