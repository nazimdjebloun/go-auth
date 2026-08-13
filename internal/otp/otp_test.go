package otp

import (
	"strings"
	"testing"
)

func TestGenerate_Length(t *testing.T) {
	for _, n := range []int{1, 6, 8, 16, 32} {
		code, err := Generate(n)
		if err != nil {
			t.Fatalf("Generate(%d): %v", n, err)
		}
		if len(code) != n {
			t.Errorf("Generate(%d): got length %d", n, len(code))
		}
	}
}

func TestGenerate_AlphabetOnly(t *testing.T) {
	code, err := Generate(200)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, ch := range code {
		if !strings.ContainsRune(Alphabet, ch) {
			t.Fatalf("character %q not in Alphabet", ch)
		}
	}
}

func TestGenerateNumeric_Length(t *testing.T) {
	for _, n := range []int{1, 6, 8} {
		code, err := GenerateNumeric(n)
		if err != nil {
			t.Fatalf("GenerateNumeric(%d): %v", n, err)
		}
		if len(code) != n {
			t.Errorf("GenerateNumeric(%d): got length %d", n, len(code))
		}
	}
}

func TestGenerateNumeric_DigitsOnly(t *testing.T) {
	code, err := GenerateNumeric(200)
	if err != nil {
		t.Fatalf("GenerateNumeric: %v", err)
	}
	for _, ch := range code {
		if !strings.ContainsRune(digits, ch) {
			t.Fatalf("character %q is not a digit", ch)
		}
	}
}

func TestGenerate_ZeroLength(t *testing.T) {
	code, err := Generate(0)
	if err != nil {
		t.Fatalf("Generate(0): %v", err)
	}
	if code != "" {
		t.Errorf("expected empty string for length 0, got %q", code)
	}
}

// TestGenerate_Distribution is a statistical smoke test, not a proof of
// randomness: over a large sample, every alphabet character should appear
// with roughly the expected frequency. A single wildly over/under
// represented character would suggest a broken generator (e.g. modulo bias
// or a fixed seed), not normal sampling variance.
func TestGenerate_Distribution(t *testing.T) {
	const samples = 20000
	counts := make(map[rune]int, len(Alphabet))
	for i := 0; i < samples; i++ {
		code, err := Generate(1)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		counts[rune(code[0])]++
	}

	if len(counts) != len(Alphabet) {
		t.Errorf("expected all %d alphabet characters to appear across %d samples, saw %d distinct", len(Alphabet), samples, len(counts))
	}

	expected := float64(samples) / float64(len(Alphabet))
	// Generous tolerance (40%) — this is a smoke test for a broken
	// generator, not a rigorous chi-squared test.
	tolerance := expected * 0.4
	for _, ch := range Alphabet {
		got := float64(counts[ch])
		if got < expected-tolerance || got > expected+tolerance {
			t.Errorf("character %q appeared %d times, want ~%.0f (+/- %.0f)", ch, counts[ch], expected, tolerance)
		}
	}
}

func TestGenerateNumeric_Distribution(t *testing.T) {
	const samples = 20000
	counts := make(map[rune]int, len(digits))
	for i := 0; i < samples; i++ {
		code, err := GenerateNumeric(1)
		if err != nil {
			t.Fatalf("GenerateNumeric: %v", err)
		}
		counts[rune(code[0])]++
	}

	expected := float64(samples) / float64(len(digits))
	tolerance := expected * 0.4
	for _, ch := range digits {
		got := float64(counts[ch])
		if got < expected-tolerance || got > expected+tolerance {
			t.Errorf("digit %q appeared %d times, want ~%.0f (+/- %.0f)", ch, counts[ch], expected, tolerance)
		}
	}
}

func TestGenerate_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	const n = 500
	for i := 0; i < n; i++ {
		code, err := Generate(16)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if seen[code] {
			t.Fatalf("duplicate 16-char code generated across only %d samples: %q", n, code)
		}
		seen[code] = true
	}
}
