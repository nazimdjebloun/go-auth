package service

import (
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
)

func TestPasswordPolicyDefault(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "ab1", true},
		{"exactly 8 with letter+digit", "pass1234", false},
		{"8 chars no digit", "password", true},
		{"8 chars no letter", "12345678", true},
		{"valid mixed", "abc12345", false},
		{"empty", "", true},
		{"above 128 chars", string(make([]byte, 129)), true},
	}
	p := domain.PasswordPolicy{MinLength: 8, RequireDigit: true}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.password)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPasswordPolicyMinLength(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 10, RequireDigit: true}

	err := p.Validate("abc1234567")
	if err != nil {
		t.Fatalf("10-char password with digit should be valid: %v", err)
	}

	err = p.Validate("abc123456")
	if err == nil {
		t.Fatal("9-char password should be too short")
	}

	err = p.Validate("abc1234567")
	if err != nil {
		t.Fatalf("10-char password with letter+digit should be valid: %v", err)
	}
}

func TestPasswordPolicyUppercase(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 8, RequireUppercase: true, RequireDigit: true}

	err := p.Validate("password1")
	if err == nil {
		t.Fatal("expected error for missing uppercase")
	}

	err = p.Validate("Password1")
	if err != nil {
		t.Fatalf("password with uppercase should be valid: %v", err)
	}
}

func TestPasswordPolicySpecial(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 8, RequireSpecial: true, RequireDigit: true}

	err := p.Validate("password1")
	if err == nil {
		t.Fatal("expected error for missing special char")
	}

	err = p.Validate("passw0rd!")
	if err != nil {
		t.Fatalf("password with special char should be valid: %v", err)
	}
}

func TestPasswordPolicyAllRequirements(t *testing.T) {
	p := domain.PasswordPolicy{
		MinLength:        12,
		RequireUppercase: true,
		RequireDigit:     true,
		RequireSpecial:   true,
	}

	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"missing uppercase and special", "abcdefgh1234", true},
		{"missing digit and special", "ABCDefghijkl", true},
		{"missing only uppercase", "abcdefg!2345", true},
		{"missing only special", "Abcdefgh1234", true},
		{"too short", "Abc1!x", true},
		{"valid", "Abcdefgh!234", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Validate(tt.password)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPasswordPolicyMaxLength(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 8, RequireDigit: true}
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	long[0] = '1'
	err := p.Validate(string(long))
	if err == nil {
		t.Fatal("expected error for >128 char password")
	}

	short := make([]byte, 128)
	for i := range short {
		short[i] = 'a'
	}
	short[0] = '1'
	err = p.Validate(string(short))
	if err != nil {
		t.Fatalf("128-char password with digit should be valid: %v", err)
	}
}

func TestPasswordPolicyUnicode(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 4, RequireDigit: true}
	err := p.Validate("日本語1")
	if err != nil {
		t.Fatalf("unicode letters with digit should be valid: %v", err)
	}
	err = p.Validate("日本語a")
	if err == nil {
		t.Fatal("expected error for missing digit")
	}
}

func TestPasswordPolicyErrorMessages(t *testing.T) {
	p := domain.PasswordPolicy{MinLength: 8, RequireDigit: true}

	err := p.Validate("short")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Code != "weak_password" {
		t.Fatalf("expected weak_password code, got %s", err.Code)
	}
	if err.Message != "Password must be at least 8 characters" {
		t.Fatalf("unexpected message: %s", err.Message)
	}

	err = p.Validate("12345678")
	if err == nil {
		t.Fatal("expected error for no letter")
	}
	if err.Message != "Password must be at least 8 characters with a letter" {
		t.Fatalf("unexpected message: %s", err.Message)
	}

	err = p.Validate("abcdefgh")
	if err == nil {
		t.Fatal("expected error for no digit")
	}
	if err.Message != "Password must be at least 8 characters with a digit" {
		t.Fatalf("unexpected message: %s", err.Message)
	}

	p2 := domain.PasswordPolicy{MinLength: 10, RequireUppercase: true, RequireSpecial: true, RequireDigit: true}
	err = p2.Validate("abcdefghij1")
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Message != "Password must be at least 10 characters with an uppercase letter, a special character" {
		t.Fatalf("unexpected message: %s", err.Message)
	}
}
