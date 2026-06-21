package domain

import (
	"fmt"
	"net/http"
	"strings"
	"unicode"
)

type PasswordPolicy struct {
	MinLength        int
	RequireUppercase bool
	RequireDigit     bool
	RequireSpecial   bool
}

func (p PasswordPolicy) Validate(password string) *AuthError {
	if p.MinLength == 0 {
		p.MinLength = 8
	}
	if len(password) < p.MinLength {
		return NewError("weak_password",
			fmt.Sprintf("Password must be at least %d characters", p.MinLength),
			http.StatusBadRequest)
	}
	if len(password) > 128 {
		return NewError("weak_password", "Password must be no more than 128 characters", http.StatusBadRequest)
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
	if !hasLetter {
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
		return NewError("weak_password", msg, http.StatusBadRequest)
	}

	return nil
}
