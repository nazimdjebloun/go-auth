package domain

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzPasswordPolicyValidate probes every rule boundary against arbitrary
// (password, policy) pairs. The oracle recomputes the policy's own stated
// rules, so divergences — a too-short or over-limit password accepted with a
// nil error, a required class ignored, or a non-weak_password error escaping —
// surface as failures. It also keeps an eye on the byte-vs-rune question the
// implementation documents: length uses Unicode code points. Algorithm-specific
// byte constraints are checked by the hashing pipeline, not by this policy.
func FuzzPasswordPolicyValidate(f *testing.F) {
	for _, s := range []string{
		"",
		"a",
		"abcdefgh",
		"Av0cado!xylophone",
		"password",
		"Passw0rd!",
		"Ünïcödé123!",
		"你好世界123!",
		"a\x00b",
		"   ",
		strings.Repeat("x", 71),
		strings.Repeat("x", 72),
		strings.Repeat("x", 73),
		strings.Repeat("é", 40), // 80 bytes of multibyte characters
	} {
		f.Add(s, 0, false, false, false)
		f.Add(s, 8, true, true, true)
		f.Add(s, 12, true, false, false)
		f.Add(s, 72, false, true, true)
	}
	f.Fuzz(func(t *testing.T, password string, minLength int, requireUppercase, requireDigit, requireSpecial bool) {
		p := PasswordPolicy{
			MinLength:        minLength,
			RequireUppercase: requireUppercase,
			RequireDigit:     requireDigit,
			RequireSpecial:   requireSpecial,
		}
		err := p.Validate(password)

		resolved := p.WithDefaults()

		var hasLetter, hasUpper, hasDigit, hasSpecial bool
		for _, ch := range password {
			switch {
			case unicode.IsUpper(ch):
				hasUpper = true
				hasLetter = true
			case unicode.IsLower(ch):
				hasLetter = true
			case unicode.IsLetter(ch):
				hasLetter = true
			case unicode.IsDigit(ch):
				hasDigit = true
			case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
				hasSpecial = true
			}
		}

		satisfied := resolved.ValidateConfig() == nil && utf8.ValidString(password) &&
			utf8.RuneCountInString(password) >= resolved.MinLength &&
			utf8.RuneCountInString(password) <= resolved.MaxLength &&
			(!resolved.RequireLetter || hasLetter) &&
			(!resolved.RequireUppercase || hasUpper) &&
			(!resolved.RequireDigit || hasDigit) &&
			(!resolved.RequireSpecial || hasSpecial)

		if err == nil && !satisfied {
			t.Errorf("Validate(%q, %+v) accepted a password that violates the policy", password, p)
		}
		if err != nil {
			ae, isAuthError := err.(*AuthError)
			if !isAuthError {
				t.Fatalf("Validate(%q, %+v) returned %T, want *AuthError", password, p, err)
			}
			if ae.Code != "weak_password" {
				t.Errorf("Validate(%q, %+v) returned code %q, want weak_password", password, p, ae.Code)
			}
			if ae.Message == "" {
				t.Errorf("Validate(%q, %+v) returned an empty message", password, p)
			}
		}
	})
}
