package argon2id

import (
	"errors"
	"strings"
	"testing"
)

func fastOptions() Options {
	return Options{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func TestDefaultOptions_RoundTrip(t *testing.T) {
	h := New(DefaultOptions())
	stored, err := h.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("unexpected encoded hash: %q", stored)
	}
	if err := h.Compare("Passw0rd!", stored); err != nil {
		t.Fatalf("round-trip compare: %v", err)
	}
}

func TestCompare_WrongPassword(t *testing.T) {
	h := New(fastOptions())
	stored, err := h.Hash("correct-password")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Compare("wrong-password", stored); !errors.Is(err, ErrPasswordMismatch) {
		t.Fatalf("wrong password error = %v, want ErrPasswordMismatch", err)
	}
}

func TestCompare_UsesStoredParameters(t *testing.T) {
	oldOptions := fastOptions()
	oldOptions.Memory = 12 * 1024
	oldOptions.Iterations = 2
	stored, err := New(oldOptions).Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if err := New(DefaultOptions()).Compare("Passw0rd!", stored); err != nil {
		t.Fatalf("configured defaults should verify stored old parameters: %v", err)
	}
}

func TestHash_UsesFreshSalt(t *testing.T) {
	h := New(fastOptions())
	first, err := h.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two hashes of the same password should use different salts")
	}
	if err := h.Compare("Passw0rd!", first); err != nil {
		t.Fatalf("first hash did not verify: %v", err)
	}
	if err := h.Compare("Passw0rd!", second); err != nil {
		t.Fatalf("second hash did not verify: %v", err)
	}
}

func TestCompare_CorruptedOrTruncatedHashFailsClosed(t *testing.T) {
	h := New(fastOptions())
	cases := []string{
		"",
		"$argon2id$",
		"$argon2id$v=19$m=8192,t=1,p=1$",
		"$argon2id$v=18$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=4294967295,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=8192,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=8192,t=1,p=0$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=8192,t=1,p=1$%%%$aGFzaGhhc2hoYXNoaGFzaA",
	}
	for _, stored := range cases {
		t.Run(stored, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Compare panicked for malformed hash: %v", recovered)
				}
			}()
			if err := h.Compare("Passw0rd!", stored); !errors.Is(err, ErrInvalidHash) {
				t.Fatalf("Compare error = %v, want ErrInvalidHash", err)
			}
		})
	}
}

func TestHash_InvalidOptionsReturnErrorInsteadOfPanicking(t *testing.T) {
	if _, err := New(Options{}).Hash("Passw0rd!"); err == nil {
		t.Fatal("zero options should fail")
	}
}
