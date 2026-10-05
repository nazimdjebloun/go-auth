package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/hasher/registry"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

// rehashLoginService is the full wiring rehash-on-login tests need: an
// AuthService built with a registry.Registry as its hasher — the same shape
// goauth.New produces — plus the mock repos the constructor requires.
type rehashLoginService struct {
	*AuthService
	users *testutil.MockUserRepo
}

// newRehashLoginService builds the service around a registry of current and
// legacy hasher, mirroring goauth.New's construction (registry wrapped over
// the configured hasher, bcrypt as legacy).
func newRehashLoginService(t *testing.T, current, legacy rehashHasher) *rehashLoginService {
	t.Helper()
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	reg, err := registry.New(current, legacy)
	if err != nil {
		t.Fatalf("registry build: %v", err)
	}
	svc := NewAuthService(&testutil.MockTxManager{}, users, sessions, tokens, reg, gen, nil, defaultTestConfig(), sessSvc, nil, nil)
	return &rehashLoginService{AuthService: svc, users: users}
}

// rehashHasher is the local alias keeping constructor signatures short.
type rehashHasher = port.Hasher

type countingHasher struct {
	port.Hasher
	hashCalls int
}

type racingPasswordRepo struct {
	*testutil.MockUserRepo
	updateCalls int
}

func (r *racingPasswordRepo) UpdatePasswordHash(_ context.Context, _, _ string, _ *uint32, _ string, _ *uint32, _ time.Time) (bool, error) {
	r.updateCalls++
	return false, nil
}

func (h *countingHasher) Hash(password string) (string, error) {
	h.hashCalls++
	return h.Hasher.Hash(password)
}

// seedPasswordUser inserts a user with a caller-supplied stored hash — the
// shape of a pre-migration row: the hash exists, possibly not in the current
// hasher's format.
func seedPasswordUser(t *testing.T, users *testutil.MockUserRepo, email, storedHash string) *domain.User {
	t.Helper()
	now := time.Now().UTC()
	u := &domain.User{
		ID:           "user-" + email,
		Email:        email,
		PasswordHash: &storedHash,
		Name:         "Legacy User",
		Role:         domain.RoleUser,
		IsVerified:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := users.Create(context.Background(), u); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// TestRehashOnLogin_LegacyBcryptRowUpgradesOnce: the core scenario. A bcrypt
// row under a non-bcrypt current hasher logs in fine, gets re-hashed to
// current's format exactly once, and the second login finds nothing to
// upgrade.
func TestRehashOnLogin_LegacyBcryptRowUpgradesOnce(t *testing.T) {
	const password = "Passw0rd!"
	legacyHash, err := hasher.New(12).Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	current := &countingHasher{Hasher: argonFakeHasher{}}
	svc := newRehashLoginService(t, current, hasher.New(12))
	probeHashCalls := current.hashCalls
	seedPasswordUser(t, svc.users, "legacy@example.com", legacyHash)

	// First login: verifies against bcrypt, rehashes to argon format.
	res, aerr := svc.Login(context.Background(), api.LoginInput{
		Email:    "legacy@example.com",
		Password: password,
	})
	if aerr != nil {
		t.Fatalf("login against legacy bcrypt row failed: %v", aerr)
	}
	if res.Session == nil {
		t.Fatal("login should issue a session")
	}
	after, err := svc.users.GetByEmail(context.Background(), "legacy@example.com")
	if err != nil || after == nil {
		t.Fatalf("reload user: %v", err)
	}
	if after.PasswordHash == nil || !strings.HasPrefix(*after.PasswordHash, "$argon2id$") {
		got := "<nil>"
		if after.PasswordHash != nil {
			got = *after.PasswordHash
		}
		t.Fatalf("stored hash should be re-hashed to argon format, got %q", got)
	}
	upgraded := *after.PasswordHash
	if current.hashCalls != probeHashCalls+1 {
		t.Fatalf("first login should hash exactly once for the upgrade: got %d calls, want %d", current.hashCalls, probeHashCalls+1)
	}

	// Second login with the same password: verifies against the argon row
	// (proving the re-hashed row is round-trippable) and does NOT rehash
	// again — the hash is identical to the first login's output.
	res2, aerr := svc.Login(context.Background(), api.LoginInput{
		Email:    "legacy@example.com",
		Password: password,
	})
	if aerr != nil {
		t.Fatalf("second login failed: %v", aerr)
	}
	if res2.Session == nil {
		t.Fatal("second login should issue a session")
	}
	after2, err := svc.users.GetByEmail(context.Background(), "legacy@example.com")
	if err != nil || after2 == nil {
		t.Fatalf("reload user: %v", err)
	}
	if after2.PasswordHash == nil || *after2.PasswordHash != upgraded {
		t.Fatal("second login should not rehash — hash already in current format")
	}
	if current.hashCalls != probeHashCalls+1 {
		t.Fatalf("second login should not hash again: got %d calls, want %d", current.hashCalls, probeHashCalls+1)
	}
}

// TestRehashOnLogin_WrongPasswordDoesNotRehash: the upgrade happens only
// after a successful Compare — a wrong password must leave the stored hash
// untouched, or a failed guess would rewrite the row.
func TestRehashOnLogin_WrongPasswordDoesNotRehash(t *testing.T) {
	const password = "Passw0rd!"
	legacyHash, err := hasher.New(12).Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	svc := newRehashLoginService(t, argonFakeHasher{}, hasher.New(12))
	seedPasswordUser(t, svc.users, "legacy@example.com", legacyHash)

	_, aerr := svc.Login(context.Background(), api.LoginInput{
		Email:    "legacy@example.com",
		Password: "WrongPass1!",
	})
	if aerr == nil {
		t.Fatal("wrong password should fail login")
	}
	after, err := svc.users.GetByEmail(context.Background(), "legacy@example.com")
	if err != nil || after == nil {
		t.Fatalf("reload user: %v", err)
	}
	if after.PasswordHash == nil || *after.PasswordHash != legacyHash {
		t.Fatal("failed login must not rehash — stored hash should be untouched")
	}
}

// TestRehashOnLogin_CostChangeUpgradesRow: WithBcryptCost's end-to-end
// contract at the service level — same algorithm, higher cost, row upgraded
// on login without any other action.
func TestRehashOnLogin_CostChangeUpgradesRow(t *testing.T) {
	const password = "Passw0rd!"
	h12, err := hasher.New(12).Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	svc := newRehashLoginService(t, hasher.New(14), nil)
	seedPasswordUser(t, svc.users, "cost@example.com", h12)

	if _, aerr := svc.Login(context.Background(), api.LoginInput{
		Email:    "cost@example.com",
		Password: password,
	}); aerr != nil {
		t.Fatalf("login against cost-12 row failed: %v", aerr)
	}
	after, err := svc.users.GetByEmail(context.Background(), "cost@example.com")
	if err != nil || after == nil {
		t.Fatalf("reload user: %v", err)
	}
	if after.PasswordHash == nil || !strings.HasPrefix(*after.PasswordHash, "$2a$14$") {
		t.Fatalf("stored hash should be re-hashed at cost 14, got %q", *after.PasswordHash)
	}
}

// TestRehashOnLogin_AlreadyCurrentFormatNoOp: a row already in current's
// format must not be rewritten — no UPDATE, hash byte-identical after login.
func TestRehashOnLogin_AlreadyCurrentFormatNoOp(t *testing.T) {
	const password = "Passw0rd!"
	h, err := hasher.New(12).Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	svc := newRehashLoginService(t, hasher.New(12), nil)
	seedPasswordUser(t, svc.users, "fresh@example.com", h)

	if _, aerr := svc.Login(context.Background(), api.LoginInput{
		Email:    "fresh@example.com",
		Password: password,
	}); aerr != nil {
		t.Fatalf("login failed: %v", aerr)
	}
	after, err := svc.users.GetByEmail(context.Background(), "fresh@example.com")
	if err != nil || after == nil {
		t.Fatalf("reload user: %v", err)
	}
	if after.PasswordHash == nil || *after.PasswordHash != h {
		t.Fatal("same-format login must leave the stored hash byte-identical")
	}
}

// TestRehashOnLogin_UnknownPrefixFailsClosedAtLogin: a corrupted row fails
// login without panicking or falling back to the current hasher. The public
// result stays invalid_credentials so the damaged row is not enumerable.
func TestRehashOnLogin_UnknownPrefixFailsClosedAtLogin(t *testing.T) {
	svc := newRehashLoginService(t, argonFakeHasher{}, hasher.New(12))
	seedPasswordUser(t, svc.users, "corrupt@example.com", "$scrypt$N:2:1$salt$hash")

	_, aerr := svc.Login(context.Background(), api.LoginInput{
		Email:    "corrupt@example.com",
		Password: "Passw0rd!",
	})
	if aerr == nil {
		t.Fatal("corrupted hash should fail login")
	}
	if !errors.Is(aerr, domain.ErrInvalidCredentials) {
		t.Fatalf("expected invalid_credentials, got %v", aerr)
	}
	// The account still exists and its row is untouched.
	after, err := svc.users.GetByEmail(context.Background(), "corrupt@example.com")
	if err != nil || after == nil {
		t.Fatalf("reload user: %v", err)
	}
	if after.PasswordHash == nil || *after.PasswordHash != "$scrypt$N:2:1$salt$hash" {
		t.Fatal("failed login must leave the corrupted row untouched")
	}
}

// TestRehashOnLogin_BareHasherKeepsWorking: direct service wiring that hands
// AuthService a plain port.Hasher (no registry) gets today's behavior —
// no rehash path, no dummy-hash indirection, login works.
func TestRehashOnLogin_BareHasherKeepsWorking(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(&testutil.MockTxManager{}, users, sessions, tokens, &testutil.MockHasher{}, gen, nil, defaultTestConfig(), sessSvc, nil, nil)
	if _, aerr := svc.Register(context.Background(), api.RegisterInput{
		Email:    "bare@example.com",
		Password: "Passw0rd!",
		Name:     "Bare",
	}); aerr != nil {
		t.Fatalf("register: %v", aerr)
	}
	res, aerr := svc.Login(context.Background(), api.LoginInput{
		Email:    "bare@example.com",
		Password: "Passw0rd!",
	})
	if aerr != nil {
		t.Fatalf("login with bare hasher: %v", aerr)
	}
	if res.Session == nil {
		t.Fatal("login should issue a session")
	}
}

func TestRehashOnLogin_DoesNotOverwriteConcurrentPasswordChange(t *testing.T) {
	const password = "Passw0rd!"
	legacyHash, err := hasher.New(12).Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	users := &racingPasswordRepo{MockUserRepo: testutil.NewMockUserRepo()}
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	reg, err := registry.New(argonFakeHasher{}, hasher.New(12))
	if err != nil {
		t.Fatal(err)
	}
	peppered, err := NewPasswordHasher(reg, 1, map[uint32][]byte{1: []byte("password pepper for race test")})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewAuthService(&testutil.MockTxManager{}, users, sessions, tokens, peppered, gen, nil, defaultTestConfig(), newTestSessionService(sessions, gen), nil, nil)
	seedPasswordUser(t, users.MockUserRepo, "race@example.com", legacyHash)

	if _, err := svc.Login(context.Background(), api.LoginInput{Email: "race@example.com", Password: password}); err != nil {
		t.Fatalf("login should remain usable when guarded update loses race: %v", err)
	}
	if users.updateCalls != 1 {
		t.Fatalf("guarded password update calls = %d, want 1", users.updateCalls)
	}
	stored, err := users.GetByEmail(context.Background(), "race@example.com")
	if err != nil || stored == nil || stored.PasswordHash == nil || *stored.PasswordHash != legacyHash {
		t.Fatal("lost-race rehash changed the stored password")
	}
}
