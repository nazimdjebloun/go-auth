package service

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/hasher/argon2id"
	"github.com/nazimdjebloun/go-auth/hasher/registry"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestLoginDummyVerificationUsesPasswordPipeline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version uint32
	}{
		{"unpeppered", 0},
		{"peppered", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pepper := []byte("independent-password-pepper-key")
			pipeline, _, current := newRecordingPasswordHasher(t, tc.version, map[uint32][]byte{1: pepper})
			users := testutil.NewMockUserRepo()
			if err := users.Create(context.Background(), &domain.User{
				ID: "passwordless", Email: "passwordless@example.com",
			}); err != nil {
				t.Fatal(err)
			}
			svc := &AuthService{users: users, hasher: pipeline}
			const candidate = "WrongPassword1!"
			for _, email := range []string{"missing@example.com", "passwordless@example.com"} {
				_, err := svc.Login(context.Background(), api.LoginInput{Email: email, Password: candidate})
				if !errors.Is(err, domain.ErrInvalidCredentials) {
					t.Fatalf("Login(%q) = %v, want invalid_credentials", email, err)
				}
			}
			want := candidate
			if tc.version != 0 {
				want = pepperPassword(candidate, pepper)
			}
			if !reflect.DeepEqual(current.compareInputs, []string{want, want}) {
				t.Fatalf("configured KDF inputs = %q, want two comparisons with %q", current.compareInputs, want)
			}
			if len(current.hashInputs) != 0 {
				t.Fatal("dummy login minted a new hash instead of using the startup probe")
			}
		})
	}
}

type dummyVerificationHasher struct {
	port.Hasher
	compared []string
}

func (h *dummyVerificationHasher) Compare(password, stored string) error {
	h.compared = append(h.compared, stored)
	return h.Hasher.Compare(password, stored)
}

func TestLoginDummyVerificationUsesConfiguredAlgorithmAndParameters(t *testing.T) {
	for _, tc := range []struct {
		name   string
		hasher port.Hasher
	}{
		{"bcrypt cost 5", hasher.New(5)},
		{"argon2id", argon2id.New(argon2id.Options{
			Memory: 64, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := &dummyVerificationHasher{Hasher: tc.hasher}
			reg, err := registry.New(current, hasher.New(4))
			if err != nil {
				t.Fatal(err)
			}
			pipeline, err := NewPasswordHasher(reg, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			current.compared = nil
			svc := &AuthService{users: testutil.NewMockUserRepo(), hasher: pipeline}
			_, err = svc.Login(context.Background(), api.LoginInput{Email: "missing@example.com", Password: "WrongPassword1!"})
			if !errors.Is(err, domain.ErrInvalidCredentials) {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(current.compared, []string{reg.DummyHash()}) {
				t.Fatal("dummy verification did not run the configured algorithm with its startup probe parameters")
			}
		})
	}
}

func TestLoginDummyVerificationUsesRegistry(t *testing.T) {
	_, registry, current := newRecordingPasswordHasher(t, 0, nil)
	const candidate = "WrongPassword1!"
	svc := &AuthService{users: testutil.NewMockUserRepo(), hasher: registry}
	_, err := svc.Login(context.Background(), api.LoginInput{Email: "missing@example.com", Password: candidate})
	if !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(current.compareInputs, []string{candidate}) {
		t.Fatalf("configured KDF inputs = %q, want one registry comparison", current.compareInputs)
	}
}
