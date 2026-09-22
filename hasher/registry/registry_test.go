package registry

import (
	"errors"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/hasher/argon2id"
	"github.com/nazimdjebloun/go-auth/port"
)

// argonFakeHasher stands in for a consumer's Argon2id implementation: an
// MCF-style format with a distinct identifying prefix, deterministic output
// for test reproducibility, and a Compare strict about format so the
// fail-closed path is observable. Nothing here is a real KDF — the registry
// only ever relies on the format properties (self-identifying prefix,
// round-trippable), which is exactly what it asks of a real hasher too.
type argonFakeHasher struct{}

func (argonFakeHasher) Hash(password string) (string, error) {
	return "$argon2id$Zml4ZWRzYWx0Zm9ydGVzdA$" + password, nil
}

func (argonFakeHasher) Compare(password, stored string) error {
	if !strings.HasPrefix(stored, "$argon2id$") {
		return ErrUnsupportedHashFormat
	}
	h, _ := argonFakeHasher{}.Hash(password)
	if h != stored {
		return domain.ErrInvalidCredentials
	}
	return nil
}

// shaFakeHasher is a second non-bcrypt implementation with a different
// prefix, for the two-custom-hashers dispatch cases.
type shaFakeHasher struct{}

func (shaFakeHasher) Hash(password string) (string, error) {
	return "sha512fake$" + password, nil
}

func (shaFakeHasher) Compare(password, stored string) error {
	if !strings.HasPrefix(stored, "sha512fake$") {
		return ErrUnsupportedHashFormat
	}
	h, _ := shaFakeHasher{}.Hash(password)
	if h != stored {
		return domain.ErrInvalidCredentials
	}
	return nil
}

// probeLessHasher produces output with no field separator at all — its
// hashes can't self-identify, so the registry must refuse to build with it
// as current.
type probeLessHasher struct{}

func (probeLessHasher) Hash(password string) (string, error) {
	return password, nil
}

type permissiveFakeHasher struct{}

func (permissiveFakeHasher) Hash(password string) (string, error) {
	return "$permissive$fixed$" + password, nil
}

func (permissiveFakeHasher) Compare(_, _ string) error {
	return nil
}

func (probeLessHasher) Compare(password, stored string) error {
	if password == stored {
		return nil
	}
	return domain.ErrInvalidCredentials
}

func TestHasherRegistry_BcryptCurrent_HashAndVerify(t *testing.T) {
	reg, err := New(hasher.New(12), nil)
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	h, err := reg.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$2a$") {
		t.Fatalf("Hash should use bcrypt (current), got %q", h)
	}
	if err := reg.Compare("Passw0rd!", h); err != nil {
		t.Fatalf("fresh hash should verify: %v", err)
	}
	if err := reg.Compare("wrong", h); err == nil {
		t.Fatal("wrong password should fail")
	}
	if reg.NeedsRehash(h) {
		t.Fatal("fresh hash at current's cost should not need rehash")
	}
}

func TestHasherRegistry_BcryptFamilyPrefixesAllVerify(t *testing.T) {
	// Hashes imported from systems that write $2b$/$2x$/$2y$ must verify
	// under a bcrypt current, and none of them trigger a rehash (the
	// family verifies interchangeably). Built by swapping the minor on a
	// real $2a$ hash — x/crypto parses the minor from the stored hash, so
	// a swapped-prefix hash verifies exactly like the original.
	reg, err := New(hasher.New(12), nil)
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	real, err := hasher.New(12).Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	for _, minor := range []string{"$2a$", "$2b$", "$2x$", "$2y$"} {
		stored := minor + strings.TrimPrefix(real, "$2a$")
		if err := reg.Compare("Passw0rd!", stored); err != nil {
			t.Fatalf("%s hash should verify: %v", minor, err)
		}
		if err := reg.Compare("wrong", stored); err == nil {
			t.Fatalf("%s wrong password should fail", minor)
		}
		if reg.NeedsRehash(stored) {
			t.Fatalf("%s same-family hash should not need rehash (minor version is not an algorithm change)", minor)
		}
	}
}

func TestHasherRegistry_CustomCurrent_VerifiesLegacyBcrypt(t *testing.T) {
	reg, err := New(argonFakeHasher{}, hasher.New(12))
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}

	// Hash goes in argon format
	h, err := reg.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("Hash should use argon (current), got %q", h)
	}

	// A bcrypt row written before the switch still verifies
	bh, err := hasher.New(12).Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Compare("Passw0rd!", bh); err != nil {
		t.Fatalf("legacy bcrypt row should verify: %v", err)
	}

	// Both formats dispatch correctly
	if err := reg.Compare("Passw0rd!", h); err != nil {
		t.Fatalf("argon row should verify: %v", err)
	}
	if err := reg.Compare("wrong", bh); err == nil {
		t.Fatal("wrong password against bcrypt row should fail")
	}
	if err := reg.Compare("wrong", h); err == nil {
		t.Fatal("wrong password against argon row should fail")
	}

	// Rehash decisions
	if !reg.NeedsRehash(bh) {
		t.Fatal("bcrypt row under argon current should need rehash")
	}
	if reg.NeedsRehash(h) {
		t.Fatal("fresh argon row should not need rehash")
	}
}

func TestHasherRegistry_RealArgon2idAndBcryptMixedDatabase(t *testing.T) {
	argon := argon2id.New(argon2id.Options{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	reg, err := New(argon, hasher.New(4))
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	argonHash, err := reg.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	bcryptHash, err := hasher.New(4).Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}

	if err := reg.Compare("Passw0rd!", argonHash); err != nil {
		t.Fatalf("argon2id row should dispatch to argon2id: %v", err)
	}
	if err := reg.Compare("Passw0rd!", bcryptHash); err != nil {
		t.Fatalf("bcrypt row should dispatch to bcrypt: %v", err)
	}
	if err := reg.Compare("wrong", argonHash); err == nil {
		t.Fatal("wrong password against argon2id row should fail")
	}
	if err := reg.Compare("wrong", bcryptHash); err == nil {
		t.Fatal("wrong password against bcrypt row should fail")
	}
	if reg.NeedsRehash(argonHash) {
		t.Fatal("current argon2id row should not need rehash")
	}
	if !reg.NeedsRehash(bcryptHash) {
		t.Fatal("bcrypt row under argon2id current should need rehash")
	}
}

func TestHasherRegistry_BcryptCurrentRetainsBuiltInArgon2idVerifier(t *testing.T) {
	reg, err := New(hasher.New(4))
	if err != nil {
		t.Fatal(err)
	}
	argon := argon2id.New(argon2id.Options{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	stored, err := argon.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Compare("Passw0rd!", stored); err != nil {
		t.Fatalf("bcrypt-current registry should verify built-in argon2id row: %v", err)
	}
	if !reg.NeedsRehash(stored) {
		t.Fatal("argon2id row under bcrypt current should be marked for rehash")
	}
}

func TestHasherRegistry_CustomCurrent_VerifiesCustomLegacy(t *testing.T) {
	// Two non-bcrypt algorithms: argon current, sha legacy. Rows in either
	// format verify; a sha row needs rehash.
	reg, err := New(argonFakeHasher{}, shaFakeHasher{}, hasher.New(12))
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	sh, _ := shaFakeHasher{}.Hash("Passw0rd!")
	if err := reg.Compare("Passw0rd!", sh); err != nil {
		t.Fatalf("sha legacy row should verify: %v", err)
	}
	if !reg.NeedsRehash(sh) {
		t.Fatal("sha legacy row should need rehash under argon current")
	}
}

func TestHasherRegistry_UnknownOrCorruptedPrefixFailsClosed(t *testing.T) {
	reg, err := New(argonFakeHasher{}, hasher.New(12))
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	cases := []struct {
		name, stored string
	}{
		{"unknown MCF algorithm", "$scrypt$N:2:1$base64salt$base64hash"},
		{"corrupted empty hash", ""},
		{"plaintext garbage", "not-a-hash-at-all"},
		{"truncated bcrypt prefix", "$2"},
		{"wrong separator", "argon2id:opaque"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := reg.Compare("Passw0rd!", tc.stored)
			if !errors.Is(err, ErrUnsupportedHashFormat) {
				t.Fatalf("expected unsupported_hash_format, got %v", err)
			}
		})
	}
	// A recognized prefix with a damaged body is different: dispatch
	// happened, the bcrypt hasher was consulted, and it refused on its
	// own terms (too short / unparseable). That error surfaces as-is —
	// not rewritten into unsupported_hash_format, which would make a
	// damaged row indistinguishable from a foreign algorithm in logs.
	if err := reg.Compare("Passw0rd!", "$2a$"); err == nil {
		t.Fatal("damaged bcrypt hash should not verify")
	} else if errors.Is(err, ErrUnsupportedHashFormat) {
		t.Fatalf("recognized-but-damaged bcrypt hash should fail with the hasher's own error, got unsupported_hash_format")
	}
	// The fail-closed path must not fall back to current either: a sha row
	// (registered only in the *other* registry) fails here rather than
	// being compared against argon.
	sh, _ := shaFakeHasher{}.Hash("Passw0rd!")
	if err := reg.Compare("Passw0rd!", sh); !errors.Is(err, ErrUnsupportedHashFormat) {
		t.Fatalf("unregistered sha row must fail closed, got %v", err)
	}
}

func TestHasherRegistry_UnknownPrefixNeverFallsBackToCurrent(t *testing.T) {
	reg, err := New(permissiveFakeHasher{}, hasher.New(12))
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	if err := reg.Compare("anything", "$unknown$payload"); !errors.Is(err, ErrUnsupportedHashFormat) {
		t.Fatalf("unknown prefix reached permissive current hasher: %v", err)
	}
}

func TestHasherRegistry_NonBcryptCurrentWithoutBcryptLegacyIsError(t *testing.T) {
	// Without a bcrypt verifier, every pre-migration row would lock out.
	// That's a construction error, not a runtime fail-closed.
	if _, err := New(argonFakeHasher{}); err == nil {
		t.Fatal("expected construction error when current is non-bcrypt and no legacy bcrypt verifier is given")
	}
}

func TestHasherRegistry_NonSelfIdentifyingCurrentIsError(t *testing.T) {
	if _, err := New(probeLessHasher{}, hasher.New(12)); err == nil {
		t.Fatal("expected construction error when current produces hashes with no identifying prefix")
	}
}

func TestHasherRegistry_NilCurrentIsError(t *testing.T) {
	if _, err := New(nil, hasher.New(12)); err == nil {
		t.Fatal("expected construction error for nil current hasher")
	}
	var typedNil *hasher.BcryptHasher
	if _, err := New(typedNil, hasher.New(12)); err == nil {
		t.Fatal("expected construction error for typed-nil current hasher")
	}
}

func TestHasherRegistry_BcryptCostChangeTriggersRehash(t *testing.T) {
	// WithBcryptCost's contract: same algorithm, different cost — the row
	// upgrades on next login. Verified at the registry level: cost-12 row
	// under a cost-14 current needs rehash; cost-14 row does not.
	reg14, err := New(hasher.New(14), nil)
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	h12, _ := hasher.New(12).Hash("Passw0rd!")
	h14, _ := hasher.New(14).Hash("Passw0rd!")
	if !reg14.NeedsRehash(h12) {
		t.Fatal("cost-12 row under cost-14 current should need rehash")
	}
	if reg14.NeedsRehash(h14) {
		t.Fatal("cost-14 row under cost-14 current should not need rehash")
	}
	// Both still verify — Compare reads cost from the stored hash.
	if err := reg14.Compare("Passw0rd!", h12); err != nil {
		t.Fatalf("cost-12 row should verify under cost-14 current: %v", err)
	}
}

func TestHasherRegistry_DummyHashIsCurrentFormat(t *testing.T) {
	reg, err := New(argonFakeHasher{}, hasher.New(12))
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	if !strings.HasPrefix(reg.DummyHash(), "$argon2id$") {
		t.Fatalf("dummy hash should be in current's format, got %q", reg.DummyHash())
	}
	// And it must fail a Compare (it's a hash of a fixed probe value, not
	// of any real password) — the timing path discards the result, but the
	// work must still run rather than short-circuit on format.
	if err := reg.Compare("anything", reg.DummyHash()); err == nil {
		t.Fatal("dummy hash should not verify against arbitrary input")
	}
}

type parameterizedFakeHasher struct {
	parameters string
}

func (h parameterizedFakeHasher) Hash(password string) (string, error) {
	return "$argon2id$v=19$" + h.parameters + "$salt$" + password, nil
}

func (h parameterizedFakeHasher) Compare(password, stored string) error {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[5] != password {
		return domain.ErrInvalidCredentials
	}
	return nil
}

func TestHasherRegistry_CustomParameterChangeTriggersRehash(t *testing.T) {
	reg, err := New(parameterizedFakeHasher{parameters: "m=65536,t=3,p=2"}, hasher.New(12))
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	oldHash, _ := parameterizedFakeHasher{parameters: "m=32768,t=2,p=2"}.Hash("Passw0rd!")
	currentHash, _ := reg.Hash("Passw0rd!")
	if !reg.NeedsRehash(oldHash) {
		t.Fatal("same algorithm with stale parameters should need rehash")
	}
	if reg.NeedsRehash(currentHash) {
		t.Fatal("current algorithm parameters should not need rehash")
	}
}

var _ port.Hasher = (*Registry)(nil)
var _ interface {
	port.Hasher
	NeedsRehash(string) bool
	DummyHash() string
} = (*Registry)(nil)
