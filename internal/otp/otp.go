// Package otp generates cryptographically random one-time codes.
package otp

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Alphabet contains the unambiguous characters used by Generate.
const Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// Generate returns a random code of the requested length using Alphabet.
func Generate(length int) (string, error) {
	return generate(length, Alphabet)
}

// GenerateNumeric returns a digits-only code, for codes a user types on a phone
// keypad. Digits carry ~3.3 bits each against Alphabet's 5, so numeric codes
// are paired with a shorter TTL — see SecurityConfig.TwoFactorCodeTTL.
func GenerateNumeric(length int) (string, error) {
	return generate(length, digits)
}

const digits = "0123456789"

func generate(length int, alphabet string) (string, error) {
	b := make([]byte, length)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("otp generate: %w", err)
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b), nil
}
