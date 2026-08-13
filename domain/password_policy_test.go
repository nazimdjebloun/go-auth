package domain

import (
	"strings"
	"testing"
)

func TestPasswordPolicy_DefaultMinLength(t *testing.T) {
	p := PasswordPolicy{}
	err := p.Validate("short")
	if err == nil {
		t.Fatal("expected error for password under default min length (8)")
	}
	ae, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if ae.Code != "weak_password" {
		t.Errorf("expected weak_password, got %s", ae.Code)
	}
}

func TestPasswordPolicy_MaxLength_BcryptBoundary(t *testing.T) {
	p := PasswordPolicy{MinLength: 8}

	at := strings.Repeat("a", 72)
	if err := p.Validate(at); err != nil {
		t.Errorf("expected exactly 72 bytes to pass Validate, got %v", err)
	}

	over := strings.Repeat("a", 73)
	err := p.Validate(over)
	if err == nil {
		t.Fatal("expected error for a 73-byte password")
	}
	ae, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if ae.Code != "weak_password" {
		t.Errorf("expected weak_password, got %s", ae.Code)
	}
}

// TestPasswordPolicy_MaxLength_MultiByte asserts the limit is measured in
// bytes, not runes: a password well under 128 *characters* can still exceed
// bcrypt's 72-*byte* limit if it contains multi-byte characters, and must be
// rejected by Validate (400 weak_password) rather than reaching hasher.Hash
// and failing with bcrypt.ErrPasswordTooLong (which every caller maps to a
// generic 500).
func TestPasswordPolicy_MaxLength_MultiByte(t *testing.T) {
	p := PasswordPolicy{MinLength: 8}
	// 25 "é" (2 bytes each in UTF-8) = 50 bytes, 25 runes — well under 128
	// characters, but combined with the ASCII prefix below it crosses 72
	// bytes while staying under 100 characters.
	password := strings.Repeat("a", 47) + strings.Repeat("é", 25) // 47 + 50 = 97 bytes, 72 runes
	if len([]rune(password)) >= 128 {
		t.Fatalf("test setup bug: password has %d runes, want under 128", len([]rune(password)))
	}
	if len(password) <= bcryptMaxBytes {
		t.Fatalf("test setup bug: password has %d bytes, want over %d", len(password), bcryptMaxBytes)
	}
	err := p.Validate(password)
	if err == nil {
		t.Fatal("expected error for a password over 72 bytes despite being under 128 runes")
	}
	ae, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if ae.Code != "weak_password" {
		t.Errorf("expected weak_password, got %s", ae.Code)
	}
}

func TestPasswordPolicy_RequireUppercase(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, RequireUppercase: true}
	err := p.Validate("lowercase1")
	if err == nil {
		t.Fatal("expected error when uppercase required but missing")
	}
}

func TestPasswordPolicy_RequireDigit(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, RequireDigit: true}
	err := p.Validate("NoDigitsHere")
	if err == nil {
		t.Fatal("expected error when digit required but missing")
	}
}

func TestPasswordPolicy_RequireSpecial(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, RequireSpecial: true}
	err := p.Validate("NoSpecial1")
	if err == nil {
		t.Fatal("expected error when special char required but missing")
	}
}

func TestPasswordPolicy_RequiresLetter(t *testing.T) {
	p := PasswordPolicy{MinLength: 8, RequireDigit: true}
	err := p.Validate("12345678")
	if err == nil {
		t.Fatal("expected error when no letter present")
	}
}

func TestPasswordPolicy_Valid(t *testing.T) {
	tests := []struct {
		name     string
		policy   PasswordPolicy
		password string
	}{
		{"minimal", PasswordPolicy{MinLength: 4}, "abcd"},
		{"uppercase", PasswordPolicy{MinLength: 4, RequireUppercase: true}, "Abcd"},
		{"digit", PasswordPolicy{MinLength: 4, RequireDigit: true}, "abc1"},
		{"special", PasswordPolicy{MinLength: 4, RequireSpecial: true}, "ab@d"},
		{"all", PasswordPolicy{MinLength: 8, RequireUppercase: true, RequireDigit: true, RequireSpecial: true}, "Abcdef1!"},
		{"unicode letter", PasswordPolicy{MinLength: 1, RequireDigit: true}, "é1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.policy.Validate(tt.password); err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
