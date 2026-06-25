package domain

import (
	"net/http"
	"testing"
)

func TestPasswordPolicy_DefaultMinLength(t *testing.T) {
	p := PasswordPolicy{}
	err := p.Validate("short")
	if err == nil {
		t.Fatal("expected error for password under default min length (8)")
	}
	if err.HTTPStatus != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", err.HTTPStatus)
	}
	if err.Code != "weak_password" {
		t.Errorf("expected weak_password, got %s", err.Code)
	}
}

func TestPasswordPolicy_MaxLength(t *testing.T) {
	p := PasswordPolicy{MinLength: 8}
	b := make([]byte, 129)
	for i := range b {
		b[i] = 'a'
	}
	err := p.Validate(string(b))
	if err == nil {
		t.Fatal("expected error for password over 128 characters")
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
