package service

import (
	"strings"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher/registry"
)

// argonFakeHasher is a deterministic self-identifying test hasher used by
// service-level rehash and password-pipeline tests.
type argonFakeHasher struct{}

func (argonFakeHasher) Hash(password string) (string, error) {
	return "$argon2id$Zml4ZWRzYWx0Zm9ydGVzdA$" + password, nil
}

func (argonFakeHasher) Compare(password, stored string) error {
	if !strings.HasPrefix(stored, "$argon2id$") {
		return registry.ErrUnsupportedHashFormat
	}
	h, _ := argonFakeHasher{}.Hash(password)
	if h != stored {
		return domain.ErrInvalidCredentials
	}
	return nil
}
