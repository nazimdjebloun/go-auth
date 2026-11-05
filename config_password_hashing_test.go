package goauth

import (
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"golang.org/x/crypto/bcrypt"
)

func TestWithPasswordHashingZeroValueDefaults(t *testing.T) {
	cfg, err := NewConfig(append(validConfigOpts(), WithPasswordHashing(PasswordHashingConfig{}))...)
	if err != nil {
		t.Fatal(err)
	}
	pipeline, _, err := buildPasswordHasher(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := pipeline.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	cost, err := bcrypt.Cost([]byte(stored))
	if err != nil || cost != 12 {
		t.Fatalf("zero config bcrypt cost = %d, %v; want 12", cost, err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(stored), []byte("Passw0rd!")); err != nil {
		t.Fatalf("zero config did not hash the unpeppered password: %v", err)
	}
}

func TestWithPasswordHashingReplacesEntireGroup(t *testing.T) {
	l, err := hasher.NewWorkLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	first := PasswordHashingConfig{
		Hasher: &prefixedTestHasher{}, BcryptCost: 4,
		Pepper:      PasswordPepperConfig{CurrentVersion: 1, Keys: map[uint32]string{1: strings.Repeat("p", 32)}},
		Concurrency: 1, WorkLimiter: l,
	}
	policy := domain.PasswordPolicy{MinLength: 15, MaxLength: 80, RequireSpecial: true}
	cfg, err := NewConfig(append(validConfigOpts(),
		WithPasswordHashing(first),
		WithSecurity(SecurityConfig{PasswordPolicy: policy, AllowEmailChange: true}),
		WithPasswordHashing(PasswordHashingConfig{}),
	)...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.passwordHasher != nil || cfg.bcryptCost != 0 || cfg.passwordConcurrency != 0 || cfg.passwordWorkLimiter != nil || cfg.passwordPepper.CurrentVersion != 0 || cfg.passwordPepper.Keys != nil {
		t.Fatal("empty replacement retained settings from the earlier hashing group")
	}
	if cfg.security.PasswordPolicy != policy || !cfg.security.AllowEmailChange {
		t.Fatal("hashing option changed WithSecurity settings")
	}
}

func TestWithPasswordHashingCopiesPepperKeysAndSharesLiveObjects(t *testing.T) {
	l, err := hasher.NewWorkLimiter(2)
	if err != nil {
		t.Fatal(err)
	}
	h := &prefixedTestHasher{}
	key := strings.Repeat("k", 32)
	keys := map[uint32]string{1: key}
	option := WithPasswordHashing(PasswordHashingConfig{
		Hasher: h, WorkLimiter: l,
		Pepper: PasswordPepperConfig{CurrentVersion: 1, Keys: keys},
	})
	a, err := NewConfig(append(validConfigOpts(), option)...)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewConfig(append(validConfigOpts(), option)...)
	if err != nil {
		t.Fatal(err)
	}
	keys[1] = "caller mutation"
	if a.passwordPepper.Keys[1] != key || b.passwordPepper.Keys[1] != key {
		t.Fatal("caller mutated an applied keyring")
	}
	a.passwordPepper.Keys[1] = "first config mutation"
	if b.passwordPepper.Keys[1] != key {
		t.Fatal("applying the same option shared keyring maps")
	}
	clone := b.clone()
	clone.passwordPepper.Keys[1] = "clone mutation"
	if b.passwordPepper.Keys[1] != key {
		t.Fatal("cloning shared the keyring map")
	}
	if a.passwordHasher != h || b.passwordHasher != h || clone.passwordHasher != h || a.passwordWorkLimiter != l || b.passwordWorkLimiter != l || clone.passwordWorkLimiter != l {
		t.Fatal("live hasher or shared limiter identity was lost")
	}
}
