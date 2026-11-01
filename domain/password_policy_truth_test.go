package domain

import (
	"strings"
	"testing"
)

func TestPasswordPolicyExplicitRulesAndUnicode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policy   PasswordPolicy
		password string
		valid    bool
	}{
		{"no implicit digit", PasswordPolicy{MinLength: 8}, "abcdefgh", true},
		{"no implicit letter", PasswordPolicy{MinLength: 8}, "12345678", true},
		{"symbols only", PasswordPolicy{MinLength: 8}, "!!!!!!!!", true},
		{"Unicode minimum", PasswordPolicy{MinLength: 8}, strings.Repeat("é", 7), false},
		{"Unicode exact length", PasswordPolicy{MinLength: 8, MaxLength: 8}, strings.Repeat("é", 8), true},
		{"default digit required", PasswordPolicy{}, "abcdefgh", false},
		{"default letter required", PasswordPolicy{}, "12345678", false},
		{"default upper bound", PasswordPolicy{}, strings.Repeat("a", 128) + "1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(tc.password); (err == nil) != tc.valid {
				t.Fatalf("valid=%t, error=%v", tc.valid, err)
			}
		})
	}
}

func TestPasswordPolicyRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy PasswordPolicy
	}{
		{"negative minimum", PasswordPolicy{MinLength: -1}},
		{"negative maximum", PasswordPolicy{MaxLength: -1}},
		{"impossible range", PasswordPolicy{MinLength: 20, MaxLength: 10}},
		{"impossible composition", PasswordPolicy{MinLength: 1, MaxLength: 1, RequireLetter: true, RequireDigit: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.ValidateConfig(); err == nil {
				t.Fatal("invalid settings accepted")
			}
			if err := tc.policy.Validate("anything"); err == nil {
				t.Fatal("invalid settings accepted a password")
			}
		})
	}
}
