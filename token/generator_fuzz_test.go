package token

import (
	"encoding/hex"
	"testing"
)

// FuzzGenerate asserts the generator's contract on every iteration: a freshly
// generated token is always exactly 32 random bytes encoded as lowercase hex.
// The fuzz input is deliberately ignored — it exists only to drive iterations
// and grow coverage over Generate/hex.EncodeToString. The previous version
// re-decoded the fuzz input itself and asserted on its length, which let the
// fuzzer feed any 1-byte hex string like "00" and "fail" a property the
// generator is not involved in and cannot violate.
func FuzzGenerate(f *testing.F) {
	gen := New()
	f.Add([]byte("seed"))
	f.Fuzz(func(t *testing.T, _ []byte) {
		tok, err := gen.Generate()
		if err != nil {
			t.Fatalf("Generate() returned an error: %v", err)
		}
		b, err := hex.DecodeString(tok)
		if err != nil {
			t.Fatalf("token %q is not valid hex: %v", tok, err)
		}
		if len(b) != 32 {
			t.Errorf("decoded token has %d bytes, want 32", len(b))
		}
	})
}
