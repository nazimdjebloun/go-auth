package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
)

type Generator struct {
	length int
}

func New(length int) *Generator {
	if length < 16 {
		length = 32
	}
	return &Generator{length: length}
}

func (g *Generator) Generate() (raw string, hash string, err error) {
	b := make([]byte, g.length)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw = hex.EncodeToString(b)
	hash = g.Hash(raw)
	return raw, hash, nil
}

func (g *Generator) Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
