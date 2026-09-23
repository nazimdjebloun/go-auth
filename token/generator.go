// Package token creates cryptographically random opaque tokens.
package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Generator creates opaque authentication tokens.
type Generator struct{}

// New returns a token generator.
func New() *Generator {
	return &Generator{}
}

// Generate returns a 32-byte random token encoded as hexadecimal.
func (g *Generator) Generate() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("token generate: %w", err)
	}
	return hex.EncodeToString(b), nil
}
