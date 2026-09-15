package otp

import (
	"strings"
	"testing"
)

func FuzzGenerate(f *testing.F) {
	for _, length := range []int{0, 1, 4, 6, 8, 16, 32, 64, 128} {
		f.Add(length)
	}
	f.Fuzz(func(t *testing.T, length int) {
		if length < 0 || length > 4096 {
			return
		}
		code, err := Generate(length)
		if err != nil {
			t.Fatalf("Generate(%d): %v", length, err)
		}
		if len(code) != length {
			t.Errorf("Generate(%d): got length %d", length, len(code))
		}
		for _, ch := range code {
			if !strings.ContainsRune(Alphabet, ch) {
				t.Errorf("character %q not in Alphabet", ch)
			}
		}
	})
}

func FuzzGenerateNumeric(f *testing.F) {
	for _, length := range []int{0, 1, 4, 6, 8, 16} {
		f.Add(length)
	}
	f.Fuzz(func(t *testing.T, length int) {
		if length < 0 || length > 4096 {
			return
		}
		code, err := GenerateNumeric(length)
		if err != nil {
			t.Fatalf("GenerateNumeric(%d): %v", length, err)
		}
		if len(code) != length {
			t.Errorf("GenerateNumeric(%d): got length %d", length, len(code))
		}
		for _, ch := range code {
			if !strings.ContainsRune(digits, ch) {
				t.Errorf("character %q is not a digit", ch)
			}
		}
	})
}
