package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"

	"github.com/nazimdjebloun/go-auth/port"
)

var errUnsupportedPepperVersion = errors.New("service: unsupported password pepper version")

// passwordHasher composes an algorithm-dispatching registry with an exact,
// versioned pepper keyring. A nil stored version means the row is unpeppered;
// non-nil versions select exactly one key. Verification never searches the
// keyring, which keeps work bounded and prevents ambiguous migrations.
type passwordHasher struct {
	registry       *hasherRegistry
	currentVersion uint32
	keys           map[uint32][]byte
}

// NewPasswordHasher builds the password pipeline used by every service.
// currentVersion zero leaves new hashes unpeppered while still allowing
// preloaded keys to verify rows written by newer nodes during a rolling
// deployment.
func NewPasswordHasher(registry *hasherRegistry, currentVersion uint32, keys map[uint32][]byte) (*passwordHasher, error) {
	if registry == nil {
		return nil, errors.New("password hasher: registry is nil")
	}
	cloned := make(map[uint32][]byte, len(keys))
	for version, key := range keys {
		if version == 0 {
			return nil, errors.New("password hasher: pepper version 0 is reserved")
		}
		if len(key) == 0 {
			return nil, fmt.Errorf("password hasher: pepper key version %d is empty", version)
		}
		cloned[version] = append([]byte(nil), key...)
	}
	if currentVersion != 0 {
		if _, ok := cloned[currentVersion]; !ok {
			return nil, fmt.Errorf("password hasher: current pepper version %d has no key", currentVersion)
		}
	}
	return &passwordHasher{registry: registry, currentVersion: currentVersion, keys: cloned}, nil
}

// ValidateStoredVersions is the startup fail-closed check. Every pepper
// version found in the database must be available on this instance before it
// can serve authentication traffic.
func (h *passwordHasher) ValidateStoredVersions(versions []uint32) error {
	missing := make([]uint32, 0)
	for _, version := range versions {
		if _, ok := h.keys[version]; !ok {
			missing = append(missing, version)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Slice(missing, func(i, j int) bool { return missing[i] < missing[j] })
	return fmt.Errorf("password hasher: database contains password pepper versions with no configured key: %v", missing)
}

// Hash implements port.Hasher for compatibility. Service password writes use
// hashPassword below so the matching version is persisted with the hash.
func (h *passwordHasher) Hash(password string) (string, error) {
	hash, _, err := h.hashVersioned(password)
	return hash, err
}

// Compare implements port.Hasher for compatibility and checks against the
// current representation. Reads of persisted users use comparePassword below
// and therefore select the exact version stored beside the hash.
func (h *passwordHasher) Compare(password, stored string) error {
	return h.compareVersioned(password, stored, uint32Pointer(h.currentVersion))
}

func (h *passwordHasher) hashVersioned(password string) (string, *uint32, error) {
	return h.hashVersionedAtLeast(password, nil)
}

func (h *passwordHasher) hashVersionedAtLeast(password string, minimumVersion *uint32) (string, *uint32, error) {
	version := h.currentVersion
	if minimumVersion != nil && *minimumVersion > version {
		// A password change/reset handled by an older node must not downgrade
		// a row a newer node already wrote. Safe rolling deployment preloads
		// that future key before it can appear in the database.
		if _, ok := h.keys[*minimumVersion]; !ok {
			return "", nil, fmt.Errorf(
				"%w: cannot hash at stored version %d because its key is unavailable",
				errUnsupportedPepperVersion,
				*minimumVersion,
			)
		}
		version = *minimumVersion
	}
	if version == 0 {
		hash, err := h.registry.Hash(password)
		return hash, nil, err
	}
	hash, err := h.registry.Hash(pepperPassword(password, h.keys[version]))
	return hash, uint32Pointer(version), err
}

func (h *passwordHasher) compareVersioned(password, stored string, version *uint32) error {
	if version == nil {
		return h.registry.Compare(password, stored)
	}
	key, ok := h.keys[*version]
	if !ok || *version == 0 {
		h.registry.burnDummy(stored)
		return fmt.Errorf("%w: %d", errUnsupportedPepperVersion, *version)
	}
	return h.registry.Compare(pepperPassword(password, key), stored)
}

func (h *passwordHasher) needsRehash(stored string, storedVersion *uint32) bool {
	version := uint32(0)
	if storedVersion != nil {
		version = *storedVersion
	}
	if version > h.currentVersion {
		// An older node in a rolling deployment may verify a row written by a
		// newer node because its key was preloaded. It must never downgrade it.
		return false
	}
	return version < h.currentVersion || h.registry.needsRehash(stored)
}

func (h *passwordHasher) dummyHash() string {
	return h.registry.dummyHash()
}

type versionedPasswordPipeline interface {
	hashVersioned(password string) (string, *uint32, error)
	hashVersionedAtLeast(password string, minimumVersion *uint32) (string, *uint32, error)
	compareVersioned(password, stored string, version *uint32) error
	needsRehash(stored string, version *uint32) bool
	dummyHash() string
}

func hashPasswordAtLeast(h port.Hasher, password string, minimumVersion *uint32) (string, *uint32, error) {
	if versioned, ok := h.(versionedPasswordPipeline); ok {
		return versioned.hashVersionedAtLeast(password, minimumVersion)
	}
	return hashPassword(h, password)
}

func hashPassword(h port.Hasher, password string) (string, *uint32, error) {
	if versioned, ok := h.(versionedPasswordPipeline); ok {
		return versioned.hashVersioned(password)
	}
	hash, err := h.Hash(password)
	return hash, nil, err
}

func comparePassword(h port.Hasher, password, stored string, version *uint32) error {
	if versioned, ok := h.(versionedPasswordPipeline); ok {
		return versioned.compareVersioned(password, stored, version)
	}
	return h.Compare(password, stored)
}

func uint32Pointer(value uint32) *uint32 {
	if value == 0 {
		return nil
	}
	copy := value
	return &copy
}

func pepperPassword(password string, pepper []byte) string {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(password))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

var _ port.Hasher = (*passwordHasher)(nil)
