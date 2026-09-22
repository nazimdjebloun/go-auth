package service

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/hasher/registry"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

type recordingPasswordHasher struct {
	hashInputs    []string
	compareInputs []string
}

func (h *recordingPasswordHasher) Hash(password string) (string, error) {
	h.hashInputs = append(h.hashInputs, password)
	return "$test$v=1$fixed$" + password, nil
}

func (h *recordingPasswordHasher) Compare(password, stored string) error {
	h.compareInputs = append(h.compareInputs, password)
	if stored != "$test$v=1$fixed$"+password {
		return domain.ErrInvalidCredentials
	}
	return nil
}

func newRecordingPasswordHasher(t *testing.T, currentVersion uint32, keys map[uint32][]byte) (*passwordHasher, *registry.Registry, *recordingPasswordHasher) {
	t.Helper()
	current := &recordingPasswordHasher{}
	registry, err := registry.New(current, hasher.New(4))
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	pipeline, err := NewPasswordHasher(registry, currentVersion, keys)
	if err != nil {
		t.Fatalf("password hasher build: %v", err)
	}
	current.hashInputs = nil
	current.compareInputs = nil
	return pipeline, registry, current
}

func TestPasswordHasher_CurrentVersionUsesHMACAndReturnsVersion(t *testing.T) {
	pepper := []byte("derived password pepper key version one")
	pipeline, registry, current := newRecordingPasswordHasher(t, 1, map[uint32][]byte{1: pepper})

	stored, version, err := pipeline.hashVersioned("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if version == nil || *version != 1 {
		t.Fatalf("stored version = %v, want 1", version)
	}
	wantInput := pepperPassword("Passw0rd!", pepper)
	if !reflect.DeepEqual(current.hashInputs, []string{wantInput}) {
		t.Fatalf("KDF inputs = %q, want HMAC output %q", current.hashInputs, wantInput)
	}
	if err := registry.Compare("Passw0rd!", stored); err == nil {
		t.Fatal("raw password verified a peppered hash")
	}
	if err := pipeline.compareVersioned("Passw0rd!", stored, version); err != nil {
		t.Fatalf("versioned verify: %v", err)
	}
}

func TestPasswordHasher_DisabledSkipsHMACEntirely(t *testing.T) {
	pipeline, _, current := newRecordingPasswordHasher(t, 0, map[uint32][]byte{
		1: []byte("preloaded future password pepper key"),
	})

	_, version, err := pipeline.hashVersioned("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	if version != nil {
		t.Fatalf("disabled pepper stored version %v, want nil", *version)
	}
	if !reflect.DeepEqual(current.hashInputs, []string{"Passw0rd!"}) {
		t.Fatalf("KDF input = %q; disabled pepper must pass plaintext directly", current.hashInputs)
	}
}

func TestPasswordHasher_SelectsExactStoredVersionWithoutFallback(t *testing.T) {
	key1 := []byte("derived password pepper key version one")
	key2 := []byte("derived password pepper key version two")
	pipeline, registry, current := newRecordingPasswordHasher(t, 2, map[uint32][]byte{1: key1, 2: key2})
	stored, err := registry.Hash(pepperPassword("Passw0rd!", key1))
	if err != nil {
		t.Fatal(err)
	}
	current.compareInputs = nil
	version1 := uint32(1)
	if err := pipeline.compareVersioned("Passw0rd!", stored, &version1); err != nil {
		t.Fatalf("version 1 verify: %v", err)
	}
	want := []string{pepperPassword("Passw0rd!", key1)}
	if !reflect.DeepEqual(current.compareInputs, want) {
		t.Fatalf("compare inputs = %q, want exact version only %q", current.compareInputs, want)
	}

	current.compareInputs = nil
	unknown := uint32(99)
	err = pipeline.compareVersioned("Passw0rd!", stored, &unknown)
	if !errors.Is(err, errUnsupportedPepperVersion) {
		t.Fatalf("unknown version error = %v", err)
	}
	if len(current.compareInputs) == 0 || !strings.Contains(current.compareInputs[0], "dummy") {
		t.Fatalf("unknown version did not burn the real configured verifier: %q", current.compareInputs)
	}
}

func TestPasswordHasher_UnknownVersionWithCorruptHashBurnsCurrentKDF(t *testing.T) {
	pipeline, _, current := newRecordingPasswordHasher(t, 1, map[uint32][]byte{
		1: []byte("derived password pepper key version one"),
	})
	current.compareInputs = nil
	unknown := uint32(99)
	err := pipeline.compareVersioned("Passw0rd!", "$corrupt", &unknown)
	if !errors.Is(err, errUnsupportedPepperVersion) {
		t.Fatalf("unknown version error = %v", err)
	}
	if !reflect.DeepEqual(current.compareInputs, []string{"goauth-unsupported-pepper-version-dummy"}) {
		t.Fatalf("corrupt hash dummy work = %q, want one current-KDF comparison", current.compareInputs)
	}
}

func TestPasswordHasher_StartupRejectsMissingStoredVersions(t *testing.T) {
	pipeline, _, _ := newRecordingPasswordHasher(t, 1, map[uint32][]byte{
		1: []byte("derived password pepper key version one"),
	})
	if err := pipeline.ValidateStoredVersions([]uint32{1}); err != nil {
		t.Fatalf("known stored version rejected: %v", err)
	}
	err := pipeline.ValidateStoredVersions([]uint32{2, 1})
	if err == nil || !strings.Contains(err.Error(), "[2]") {
		t.Fatalf("missing stored version error = %v", err)
	}
}

func TestPasswordHasher_OlderNodeNeverDowngradesNewerPepperVersion(t *testing.T) {
	pipeline, registry, _ := newRecordingPasswordHasher(t, 1, map[uint32][]byte{
		1: []byte("derived password pepper key version one"),
		2: []byte("derived password pepper key version two"),
	})
	stored, err := registry.Hash(pepperPassword("Passw0rd!", pipeline.keys[2]))
	if err != nil {
		t.Fatal(err)
	}
	version2 := uint32(2)
	if err := pipeline.compareVersioned("Passw0rd!", stored, &version2); err != nil {
		t.Fatalf("preloaded future version verify: %v", err)
	}
	if pipeline.needsRehash(stored, &version2) {
		t.Fatal("older node would downgrade a newer pepper version")
	}
}

func TestPasswordHasher_OlderNodePasswordWritePreservesNewerVersion(t *testing.T) {
	key1 := []byte("derived password pepper key version one")
	key2 := []byte("derived password pepper key version two")
	pipeline, registry, current := newRecordingPasswordHasher(t, 1, map[uint32][]byte{1: key1, 2: key2})
	version2 := uint32(2)
	current.hashInputs = nil

	stored, version, err := pipeline.hashVersionedAtLeast("NewPassw0rd!", &version2)
	if err != nil {
		t.Fatal(err)
	}
	if version == nil || *version != 2 {
		t.Fatalf("password write version = %v, want preserved version 2", version)
	}
	wantInput := pepperPassword("NewPassw0rd!", key2)
	if !reflect.DeepEqual(current.hashInputs, []string{wantInput}) {
		t.Fatalf("password write KDF input = %q, want v2 HMAC %q", current.hashInputs, wantInput)
	}
	if err := pipeline.compareVersioned("NewPassw0rd!", stored, version); err != nil {
		t.Fatalf("preserved-version password did not verify: %v", err)
	}
	if err := registry.Compare(pepperPassword("NewPassw0rd!", key1), stored); err == nil {
		t.Fatal("password write used the older node's v1 key")
	}
}

func TestPasswordHasher_OlderNodePasswordWriteFailsWithoutNewerKey(t *testing.T) {
	pipeline, _, current := newRecordingPasswordHasher(t, 1, map[uint32][]byte{
		1: []byte("derived password pepper key version one"),
	})
	version2 := uint32(2)

	_, _, err := pipeline.hashVersionedAtLeast("NewPassw0rd!", &version2)
	if !errors.Is(err, errUnsupportedPepperVersion) {
		t.Fatalf("hash with unavailable minimum version error = %v", err)
	}
	if len(current.hashInputs) != 0 {
		t.Fatalf("downgrade path invoked the KDF with %q", current.hashInputs)
	}
}

func TestPasswordPepper_UnpepperedLoginUpgradesOnce(t *testing.T) {
	pepper := []byte("derived password pepper key version one")
	current := &countingHasher{Hasher: argonFakeHasher{}}
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	registry, err := registry.New(current, hasher.New(4))
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := NewPasswordHasher(registry, 1, map[uint32][]byte{1: pepper})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewAuthService(users, sessions, tokens, pipeline, gen, nil, defaultTestConfig(), newTestSessionService(sessions, gen), nil, nil)
	probeHashCalls := current.hashCalls

	const password = "Passw0rd!"
	legacyHash, err := hasher.New(4).Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	seedPasswordUser(t, users, "legacy-pepper@example.com", legacyHash)
	if _, err := svc.Login(context.Background(), LoginInput{Email: "legacy-pepper@example.com", Password: password}); err != nil {
		t.Fatalf("legacy login: %v", err)
	}
	user, _ := users.GetByEmail(context.Background(), "legacy-pepper@example.com")
	if user.PasswordPepperVersion == nil || *user.PasswordPepperVersion != 1 {
		t.Fatalf("upgraded version = %v, want 1", user.PasswordPepperVersion)
	}
	if current.hashCalls != probeHashCalls+1 {
		t.Fatalf("first login hash calls = %d, want %d", current.hashCalls, probeHashCalls+1)
	}
	if _, err := svc.Login(context.Background(), LoginInput{Email: user.Email, Password: password}); err != nil {
		t.Fatalf("second login: %v", err)
	}
	if current.hashCalls != probeHashCalls+1 {
		t.Fatalf("second login rehashed again: calls = %d", current.hashCalls)
	}
}
