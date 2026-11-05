package goauth

import (
	"errors"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/hasher/argon2id"
)

type nilPolicyHasher struct {
	*hasher.BcryptHasher
	limit int
}

func (h *nilPolicyHasher) MaxPasswordBytes() int { return h.limit }

func TestPasswordPolicyTypedNilInputLimiterFailsConfiguration(t *testing.T) {
	if _, err := NewConfig(minimalOpts(WithPasswordHashing(PasswordHashingConfig{Hasher: (*nilPolicyHasher)(nil)}))...); err == nil {
		t.Fatal("typed-nil custom limiter accepted")
	}
}

func TestPasswordPolicyExplicitFalseRulesReachRegistration(t *testing.T) {
	a := buildAuth(t, minimalOpts(WithPasswordHashing(PasswordHashingConfig{BcryptCost: 4}), WithSecurity(SecurityConfig{
		PasswordPolicy: domain.PasswordPolicy{MinLength: 8},
	}))...)
	defer a.Close()
	for _, tc := range []struct{ name, password string }{
		{"no-digit", "abcdefgh"}, {"no-letter", "12345678"}, {"unicode", strings.Repeat("é", 8)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := a.Register(t.Context(), api.RegisterInput{Email: tc.name + "@example.test", Name: "Policy", Password: tc.password}); err != nil {
				t.Fatalf("explicit length-only policy was overridden: %v", err)
			}
		})
	}
}

func TestPasswordPolicyHasherSpecificInputBounds(t *testing.T) {
	password := strings.Repeat("a", 99) + "1"
	for _, name := range []string{"bcrypt", "peppered bcrypt", "argon2id"} {
		t.Run(name, func(t *testing.T) {
			hashing := PasswordHashingConfig{BcryptCost: 4}
			switch name {
			case "peppered bcrypt":
				hashing.Pepper = PasswordPepperConfig{CurrentVersion: 1, Keys: map[uint32]string{1: strings.Repeat("k", 32)}}
			case "argon2id":
				settings := argon2id.DefaultOptions()
				settings.Memory, settings.Iterations, settings.Parallelism = 64, 1, 1
				hashing.Hasher = argon2id.New(settings)
			}
			opts := minimalOpts(WithPasswordHashing(hashing))
			a := buildAuth(t, opts...)
			defer a.Close()
			result, err := a.Register(t.Context(), api.RegisterInput{Email: "bounds@example.test", Name: "Bounds", Password: password})
			if name == "bcrypt" {
				if result != nil || !errors.Is(err, domain.ErrWeakPassword) {
					t.Fatalf("bcrypt overflow must be a password-policy error: %v", err)
				}
				return
			}
			if err != nil || result == nil {
				t.Fatalf("valid long password rejected: %v", err)
			}
			if _, err := a.Login(t.Context(), api.LoginInput{Email: "bounds@example.test", Password: password}); err != nil {
				t.Fatalf("long password did not round-trip: %v", err)
			}
			if name == "argon2id" {
				// A stricter current write algorithm must not reject old credentials.
				cfg := a.cfg.clone()
				WithPasswordHashing(PasswordHashingConfig{BcryptCost: 4})(&cfg)
				b, err := New(&cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer b.Close()
				if _, err := b.Login(t.Context(), api.LoginInput{Email: "bounds@example.test", Password: password}); err != nil {
					t.Fatalf("current bcrypt write bound blocked a legacy Argon2id login: %v", err)
				}
			}
		})
	}
}

func TestPasswordPolicyInvalidSettingsFailStartup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy domain.PasswordPolicy
	}{
		{"negative minimum", domain.PasswordPolicy{MinLength: -1}},
		{"negative maximum", domain.PasswordPolicy{MaxLength: -1}},
		{"inverted range", domain.PasswordPolicy{MinLength: 20, MaxLength: 10}},
		{"bcrypt impossible minimum", domain.PasswordPolicy{MinLength: 80}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewConfig(minimalOpts(WithSecurity(SecurityConfig{PasswordPolicy: tc.policy}))...); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}
