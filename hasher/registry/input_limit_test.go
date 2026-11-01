package registry

import (
	"errors"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
)

type limitedHasher struct {
	*hasher.BcryptHasher
	limit int
}

func (h *limitedHasher) MaxPasswordBytes() int { return h.limit }
func (h *limitedHasher) Hash(password string) (string, error) {
	if len(password) > h.limit {
		return "", errors.New("custom hasher input overflow")
	}
	return h.BcryptHasher.Hash(password)
}

func TestRegistryProbeHonorsCustomInputLimit(t *testing.T) {
	r, err := New(&limitedHasher{BcryptHasher: hasher.New(4), limit: 8})
	if err != nil {
		t.Fatalf("valid small-input hasher rejected by startup probe: %v", err)
	}
	if _, err := r.Hash("abcdefgh"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Hash("abcdefghi"); !errors.Is(err, domain.ErrWeakPassword) {
		t.Fatalf("overflow: %v", err)
	}
	if _, err := New(&limitedHasher{BcryptHasher: hasher.New(4), limit: -1}); err == nil {
		t.Fatal("negative input limit accepted")
	}
}
