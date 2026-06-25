package token

import (
	"encoding/hex"
	"testing"
)

func TestGenerate_Returns64CharHex(t *testing.T) {
	gen := New()
	token, err := gen.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 {
		t.Errorf("expected 64 characters, got %d", len(token))
	}
	_, err = hex.DecodeString(token)
	if err != nil {
		t.Errorf("expected valid hex, got error: %v", err)
	}
}

func TestGenerate_UniqueTokens(t *testing.T) {
	gen := New()
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		token, err := gen.Generate()
		if err != nil {
			t.Fatal(err)
		}
		if seen[token] {
			t.Errorf("duplicate token: %s", token)
		}
		seen[token] = true
	}
}
