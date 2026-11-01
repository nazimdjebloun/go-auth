package domain

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// PasswordPolicy defines the checks applied to new passwords.
type PasswordPolicy struct {
	MinLength        int // Unicode code points; zero uses eight.
	MaxLength        int // Unicode code points; zero uses 128.
	RequireLetter    bool
	RequireUppercase bool
	RequireDigit     bool
	RequireSpecial   bool
}

// WithDefaults resolves lengths without changing explicit composition choices.
// An entirely zero policy selects eight to 128 characters with a letter and
// digit. Any nonzero policy keeps all its boolean values literally.
func (p PasswordPolicy) WithDefaults() PasswordPolicy {
	if p == (PasswordPolicy{}) {
		p.RequireLetter = true
		p.RequireDigit = true
	}
	if p.MinLength == 0 {
		p.MinLength = 8
	}
	if p.MaxLength == 0 {
		p.MaxLength = 128
	}
	return p
}

// ValidateConfig rejects impossible or negative length settings.
func (p PasswordPolicy) ValidateConfig() error {
	p = p.WithDefaults()
	if p.MinLength < 1 || p.MaxLength < p.MinLength {
		return fmt.Errorf("password policy requires 1 <= MinLength <= MaxLength")
	}
	classes := 0
	if p.RequireLetter || p.RequireUppercase {
		classes++
	}
	if p.RequireDigit {
		classes++
	}
	if p.RequireSpecial {
		classes++
	}
	if p.MaxLength < classes {
		return fmt.Errorf("password policy MaxLength cannot fit the required character classes")
	}
	return nil
}

// Validate returns error, not *AuthError, so a caller assigning the result to
// a plain `var err error` (the natural thing to do, since PasswordPolicy is
// exported and consumer-settable via WithSecurity) can't hit the typed-nil
// trap: a nil *AuthError boxed into a non-nil error interface would make
// `err != nil` true even on success.
func (p PasswordPolicy) Validate(password string) error {
	p = p.WithDefaults()
	if p.ValidateConfig() != nil {
		return NewError("weak_password", "Password policy has invalid length settings")
	}
	if !utf8.ValidString(password) {
		return NewError("weak_password", "Password must be valid UTF-8")
	}
	length := utf8.RuneCountInString(password)
	if length < p.MinLength {
		return NewError("weak_password",
			fmt.Sprintf("Password must be at least %d characters", p.MinLength))
	}
	if length > p.MaxLength {
		return NewError("weak_password",
			fmt.Sprintf("Password must be no more than %d characters", p.MaxLength))
	}

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

	var missing []string
	if p.RequireUppercase && !hasUpper {
		missing = append(missing, "an uppercase letter")
	}
	if p.RequireLetter && !hasLetter {
		missing = append(missing, "a letter")
	}
	if p.RequireDigit && !hasDigit {
		missing = append(missing, "a digit")
	}
	if p.RequireSpecial && !hasSpecial {
		missing = append(missing, "a special character")
	}

	if len(missing) > 0 {
		msg := fmt.Sprintf("Password must be at least %d characters with %s", p.MinLength, strings.Join(missing, ", "))
		return NewError("weak_password", msg)
	}

	return nil
}
