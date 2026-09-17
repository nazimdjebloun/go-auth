package goauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher/argon2id"
	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/internal/schema"
	"golang.org/x/crypto/bcrypt"
)

type prefixedTestHasher struct {
	hashCalls int
}

func (h *prefixedTestHasher) Hash(password string) (string, error) {
	h.hashCalls++
	return prefixedTestHash(password), nil
}

func (*prefixedTestHasher) Compare(password, stored string) error {
	if stored != prefixedTestHash(password) {
		return domain.ErrInvalidCredentials
	}
	return nil
}

func prefixedTestHash(password string) string {
	return "$argon2id$v=19$m=65536,t=3,p=2$fixedsalt$" + password
}

func newHasherTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	schemaSQL, err := GetSchema("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schema.SplitSQL(schemaSQL) {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	return db
}

func newAuthWithHasherTestDB(t *testing.T, db *sql.DB, extra ...Option) *Auth {
	t.Helper()
	opts := minimalOpts(extra...)
	opts = append(opts, WithApp(AppConfig{
		Name:     "app",
		BaseURL:  "https://example.com",
		Database: DatabaseConfig{Driver: DriverSQLite, DB: db},
	}))
	cfg, err := NewConfig(opts...)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func TestWithPasswordHasher_VerifiesAndRehashesLegacyBcryptOnce(t *testing.T) {
	const (
		email    = "legacy@example.com"
		password = "Passw0rd!"
	)
	db := newHasherTestDB(t)

	legacy := newAuthWithHasherTestDB(t, db)
	defer legacy.Close()
	if _, err := legacy.Register(context.Background(), RegisterInput{
		Email: email, Password: password, Name: "Legacy User",
	}); err != nil {
		t.Fatalf("register with default bcrypt: %v", err)
	}
	// Registration above exercises the public flow and creates all required
	// fields; replace only its credential with an independently generated
	// bcrypt hash representing an existing row before the algorithm switch.
	legacyHash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		t.Fatalf("build legacy bcrypt hash: %v", err)
	}
	if _, err := db.ExecContext(context.Background(),
		"UPDATE users SET password_hash = ? WHERE email = ?", string(legacyHash), email); err != nil {
		t.Fatalf("seed unpeppered legacy hash: %v", err)
	}
	current := &prefixedTestHasher{}
	a := newAuthWithHasherTestDB(t, db, WithPasswordHasher(current))
	defer a.Close()
	probeHashCalls := current.hashCalls

	if _, err := a.Login(context.Background(), LoginInput{Email: email, Password: password}); err != nil {
		t.Fatalf("login with legacy bcrypt hash: %v", err)
	}
	if current.hashCalls != probeHashCalls+1 {
		t.Fatalf("first login hash calls = %d, want %d", current.hashCalls, probeHashCalls+1)
	}

	var stored string
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE email = ?", email).Scan(&stored); err != nil {
		t.Fatalf("read upgraded hash: %v", err)
	}
	if !strings.HasPrefix(stored, "$argon2id$") {
		t.Fatalf("upgraded hash = %q, want argon2id prefix", stored)
	}

	if _, err := a.Login(context.Background(), LoginInput{Email: email, Password: password}); err != nil {
		t.Fatalf("second login with upgraded hash: %v", err)
	}
	if current.hashCalls != probeHashCalls+1 {
		t.Fatalf("second login rehashed again: hash calls = %d, want %d", current.hashCalls, probeHashCalls+1)
	}
}

func TestWithPasswordHasher_RealArgon2idRehashesBcryptOnLogin(t *testing.T) {
	const (
		email    = "argon-migration@example.com"
		password = "Passw0rd!"
	)
	db := newHasherTestDB(t)

	legacy := newAuthWithHasherTestDB(t, db, WithBcryptCost(4))
	defer legacy.Close()
	if _, err := legacy.Register(context.Background(), RegisterInput{
		Email: email, Password: password, Name: "Argon Migration",
	}); err != nil {
		t.Fatalf("register bcrypt user: %v", err)
	}

	argon := argon2id.New(argon2id.Options{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	a := newAuthWithHasherTestDB(t, db, WithPasswordHasher(argon))
	defer a.Close()

	if _, err := a.Login(context.Background(), LoginInput{Email: email, Password: password}); err != nil {
		t.Fatalf("login with bcrypt row under argon2id current: %v", err)
	}
	var upgraded string
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE email = ?", email).Scan(&upgraded); err != nil {
		t.Fatalf("read upgraded hash: %v", err)
	}
	if !strings.HasPrefix(upgraded, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("upgraded hash = %q, want configured argon2id format", upgraded)
	}

	if _, err := a.Login(context.Background(), LoginInput{Email: email, Password: password}); err != nil {
		t.Fatalf("second login with argon2id row: %v", err)
	}
	var afterSecondLogin string
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE email = ?", email).Scan(&afterSecondLogin); err != nil {
		t.Fatalf("read hash after second login: %v", err)
	}
	if afterSecondLogin != upgraded {
		t.Fatal("second argon2id login should not rehash an already-current row")
	}
}

func TestWithBcryptCost_UsesConfiguredCost(t *testing.T) {
	a := buildAuth(t, minimalOpts(WithBcryptCost(4))...)
	defer a.Close()

	result, err := a.Register(context.Background(), RegisterInput{
		Email: "cost@example.com", Password: "Passw0rd!", Name: "Cost",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := bcrypt.Cost([]byte(*result.User.PasswordHash))
	if err != nil {
		t.Fatalf("parse bcrypt hash: %v", err)
	}
	if got != 4 {
		t.Fatalf("bcrypt cost = %d, want 4", got)
	}
}

func TestDefaultPasswordHasher_NewSignupIsNotPeppered(t *testing.T) {
	const password = "Passw0rd!"
	a := buildAuth(t, minimalOpts(WithBcryptCost(4))...)
	defer a.Close()

	result, err := a.Register(context.Background(), RegisterInput{
		Email: "unpeppered@example.com", Password: password, Name: "Unpeppered",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.PasswordHash == nil {
		t.Fatal("registered password hash is nil")
	}

	stored := []byte(*result.User.PasswordHash)
	if err := bcrypt.CompareHashAndPassword(stored, []byte(password)); err != nil {
		t.Fatalf("default new signup hash does not verify against the raw password: %v", err)
	}
	if _, err := a.Login(context.Background(), LoginInput{
		Email: "unpeppered@example.com", Password: password,
	}); err != nil {
		t.Fatalf("default unpeppered signup could not log in: %v", err)
	}
}

func TestWithPasswordHasher_Argon2idSignupIsNotPepperedByDefault(t *testing.T) {
	const password = "Passw0rd!"
	argon := argon2id.New(argon2id.Options{
		Memory:      8 * 1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	})
	a := buildAuth(t, minimalOpts(WithPasswordHasher(argon))...)
	defer a.Close()

	result, err := a.Register(context.Background(), RegisterInput{
		Email: "unpeppered-argon@example.com", Password: password, Name: "Unpeppered Argon",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.User.PasswordHash == nil {
		t.Fatal("registered password hash is nil")
	}

	// Compare directly with the configured KDF and the raw password. This
	// would fail if the no-option path accidentally applied even a zero-key
	// HMAC before Argon2id.
	if err := argon.Compare(password, *result.User.PasswordHash); err != nil {
		t.Fatalf("unpeppered Argon2id hash does not verify against the raw password: %v", err)
	}
}

func TestWithPasswordPepper_NewSignupAndLegacyMigration(t *testing.T) {
	const (
		pepperSecret = "abcdef0123456789abcdef0123456789"
		password     = "Passw0rd!"
	)
	db := newHasherTestDB(t)

	legacy := newAuthWithHasherTestDB(t, db, WithBcryptCost(4))
	defer legacy.Close()
	if _, err := legacy.Register(context.Background(), RegisterInput{
		Email: "legacy-pepper@example.com", Password: password, Name: "Legacy",
	}); err != nil {
		t.Fatalf("register unpeppered legacy user: %v", err)
	}

	pepperedAuth := newAuthWithHasherTestDB(t, db,
		WithBcryptCost(4),
		WithPasswordPepper(PasswordPepperConfig{CurrentVersion: 1, Keys: map[uint32]string{1: pepperSecret}}),
	)
	defer pepperedAuth.Close()
	newUser, err := pepperedAuth.Register(context.Background(), RegisterInput{
		Email: "new-pepper@example.com", Password: password, Name: "Peppered",
	})
	if err != nil {
		t.Fatalf("register peppered user: %v", err)
	}

	pepper := keyring.DerivePasswordPepper([]byte(pepperSecret))
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write([]byte(password))
	pepperedPassword := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	assertPeppered := func(label, stored string) {
		t.Helper()
		if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)); err == nil {
			t.Fatalf("%s hash verifies against the raw password", label)
		}
		if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(pepperedPassword)); err != nil {
			t.Fatalf("%s hash does not verify against the peppered representation: %v", label, err)
		}
	}
	assertPeppered("new signup", *newUser.User.PasswordHash)

	if _, err := pepperedAuth.Login(context.Background(), LoginInput{
		Email: "legacy-pepper@example.com", Password: password,
	}); err != nil {
		t.Fatalf("legacy unpeppered login after enabling pepper: %v", err)
	}
	var upgraded string
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE email = ?", "legacy-pepper@example.com").Scan(&upgraded); err != nil {
		t.Fatalf("read upgraded legacy hash: %v", err)
	}
	assertPeppered("upgraded legacy", upgraded)
	var upgradedVersion uint32
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_pepper_version FROM users WHERE email = ?", "legacy-pepper@example.com").Scan(&upgradedVersion); err != nil {
		t.Fatalf("read upgraded legacy pepper version: %v", err)
	}
	if upgradedVersion != 1 {
		t.Fatalf("upgraded pepper version = %d, want 1", upgradedVersion)
	}

	if _, err := pepperedAuth.Login(context.Background(), LoginInput{
		Email: "legacy-pepper@example.com", Password: password,
	}); err != nil {
		t.Fatalf("second login after pepper migration: %v", err)
	}
	var afterSecondLogin string
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE email = ?", "legacy-pepper@example.com").Scan(&afterSecondLogin); err != nil {
		t.Fatalf("read hash after second login: %v", err)
	}
	if afterSecondLogin != upgraded {
		t.Fatal("second login rehashed an already-peppered row")
	}
}

func TestWithPasswordPepper_RotationAndRollingDeployDoNotDowngrade(t *testing.T) {
	const (
		password = "Passw0rd!"
		key1     = "password-pepper-version-one-00001"
		key2     = "password-pepper-version-two-00002"
	)
	db := newHasherTestDB(t)

	v1 := newAuthWithHasherTestDB(t, db,
		WithBcryptCost(4),
		WithPasswordPepper(PasswordPepperConfig{
			CurrentVersion: 1,
			Keys:           map[uint32]string{1: key1, 2: key2},
		}),
	)
	registered, err := v1.Register(context.Background(), RegisterInput{
		Email: "rotate@example.com", Password: password, Name: "Rotate",
	})
	if err != nil {
		t.Fatalf("register under v1: %v", err)
	}
	userID := registered.User.ID
	v1.Close()

	v2 := newAuthWithHasherTestDB(t, db,
		WithBcryptCost(4),
		WithPasswordPepper(PasswordPepperConfig{
			CurrentVersion: 2,
			Keys:           map[uint32]string{1: key1, 2: key2},
		}),
	)
	if _, err := v2.Login(context.Background(), LoginInput{Email: "rotate@example.com", Password: password}); err != nil {
		t.Fatalf("login and rotate v1 to v2: %v", err)
	}
	v2.Close()

	var hashAtV2 string
	var version uint32
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash, password_pepper_version FROM users WHERE email = ?", "rotate@example.com").Scan(&hashAtV2, &version); err != nil {
		t.Fatalf("read v2 row: %v", err)
	}
	if version != 2 {
		t.Fatalf("rotated version = %d, want 2", version)
	}

	// Simulate a still-running old node after a v2 node upgraded the row. It
	// preloaded v2 during phase one, so it can verify the row, but its current
	// version remains v1 and must not write a downgrade.
	oldNode := newAuthWithHasherTestDB(t, db,
		WithBcryptCost(4),
		WithPasswordPepper(PasswordPepperConfig{
			CurrentVersion: 1,
			Keys:           map[uint32]string{1: key1, 2: key2},
		}),
	)
	defer oldNode.Close()
	if _, err := oldNode.Login(context.Background(), LoginInput{Email: "rotate@example.com", Password: password}); err != nil {
		t.Fatalf("old node failed to verify preloaded v2: %v", err)
	}
	var hashAfterOldNode string
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash, password_pepper_version FROM users WHERE email = ?", "rotate@example.com").Scan(&hashAfterOldNode, &version); err != nil {
		t.Fatalf("read row after old-node login: %v", err)
	}
	if version != 2 || hashAfterOldNode != hashAtV2 {
		t.Fatal("old node downgraded a password written with a newer pepper version")
	}

	if err := oldNode.Services.Password.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:      userID,
		OldPassword: password,
		NewPassword: "NewPassw0rd!",
	}); err != nil {
		t.Fatalf("old-node password change: %v", err)
	}
	if err := db.QueryRowContext(context.Background(),
		"SELECT password_hash, password_pepper_version FROM users WHERE email = ?", "rotate@example.com").Scan(&hashAfterOldNode, &version); err != nil {
		t.Fatalf("read row after old-node password change: %v", err)
	}
	if version != 2 {
		t.Fatalf("old-node password change downgraded pepper version to %d", version)
	}
	if _, err := oldNode.Login(context.Background(), LoginInput{Email: "rotate@example.com", Password: "NewPassw0rd!"}); err != nil {
		t.Fatalf("login after preserved-v2 password change: %v", err)
	}
}

func TestWithPasswordPepper_StartupRejectsMissingDatabaseVersion(t *testing.T) {
	const key1 = "password-pepper-version-one-00001"
	db := newHasherTestDB(t)
	v1 := newAuthWithHasherTestDB(t, db,
		WithBcryptCost(4),
		WithPasswordPepper(PasswordPepperConfig{CurrentVersion: 1, Keys: map[uint32]string{1: key1}}),
	)
	if _, err := v1.Register(context.Background(), RegisterInput{
		Email: "missing-key@example.com", Password: "Passw0rd!", Name: "Missing",
	}); err != nil {
		t.Fatal(err)
	}
	v1.Close()

	cfg, err := NewConfig(minimalOpts(
		WithApp(AppConfig{Name: "app", BaseURL: "https://example.com", Database: DatabaseConfig{Driver: DriverSQLite, DB: db}}),
		WithBcryptCost(4),
		WithPasswordPepper(PasswordPepperConfig{
			CurrentVersion: 2,
			Keys:           map[uint32]string{2: "password-pepper-version-two-00002"},
		}),
	)...)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	a, err := New(cfg)
	if a != nil {
		a.Close()
		t.Fatal("New succeeded without the key for a stored pepper version")
	}
	if err == nil || !strings.Contains(err.Error(), "[1]") {
		t.Fatalf("New error = %v, want missing stored version 1", err)
	}
}

func TestDefaultPasswordHasher_RemainsBcryptCost12(t *testing.T) {
	a := buildAuth(t, minimalOpts()...)
	defer a.Close()

	result, err := a.Register(context.Background(), RegisterInput{
		Email: "default@example.com", Password: "Passw0rd!", Name: "Default",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(*result.User.PasswordHash, "$2a$") {
		t.Fatalf("default password hash = %q, want bcrypt $2a$ prefix", *result.User.PasswordHash)
	}
	got, err := bcrypt.Cost([]byte(*result.User.PasswordHash))
	if err != nil {
		t.Fatalf("parse bcrypt hash: %v", err)
	}
	if got != 12 {
		t.Fatalf("bcrypt cost = %d, want 12", got)
	}
}

func TestWithPasswordHasher_TakesPrecedenceOverBcryptCost(t *testing.T) {
	if _, err := NewConfig(minimalOpts(
		WithBcryptCost(bcrypt.MaxCost+1),
		WithPasswordHasher(&prefixedTestHasher{}),
	)...); err != nil {
		t.Fatalf("custom hasher should make bcrypt cost inert: %v", err)
	}
}

func TestWithBcryptCost_RejectsCostAboveMaximum(t *testing.T) {
	if _, err := NewConfig(minimalOpts(WithBcryptCost(bcrypt.MaxCost + 1))...); err == nil {
		t.Fatal("expected invalid bcrypt cost to fail validation")
	}
}
