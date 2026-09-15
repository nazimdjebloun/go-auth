package token

import (
	"encoding/hex"
	"testing"
)

func FuzzGenerate(f *testing.F) {
	gen := New()
	for i := 0; i < 100; i++ {
		tok, err := gen.Generate()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(tok)
	}
	f.Fuzz(func(t *testing.T, tok string) {
		if len(tok) == 0 {
			return
		}
		b, err := hex.DecodeString(tok)
		if err != nil {
			return
		}
		if len(b) != 32 {
			t.Errorf("decoded token has %d bytes, want 32", len(b))
		}
	})
}
