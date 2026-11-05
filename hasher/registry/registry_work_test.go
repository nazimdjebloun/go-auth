package registry

import (
	"errors"
	"sync"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/hasher/argon2id"
	"github.com/nazimdjebloun/go-auth/port"
)

type blockingWorkHasher struct {
	port.Hasher
	entered chan struct{}
	release chan struct{}
}

func (h *blockingWorkHasher) Hash(password string) (string, error) {
	if password == "blocked" {
		close(h.entered)
		<-h.release
	}
	return h.Hasher.Hash(password)
}

func (h *blockingWorkHasher) Compare(password, stored string) error {
	if password == "blocked" {
		close(h.entered)
		<-h.release
	}
	return h.Hasher.Compare(password, stored)
}

func TestRegistrySharesCapacityAcrossHashVerificationAndStartup(t *testing.T) {
	l, err := hasher.NewWorkLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	h := &blockingWorkHasher{Hasher: argonFakeHasher{}, entered: make(chan struct{}), release: make(chan struct{})}
	r, err := NewWithWorkLimiter(h, l, hasher.New(4))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewWithWorkLimiter(hasher.New(4), l)
	if err != nil {
		t.Fatal(err)
	}
	argon := argon2id.New(argon2id.Options{Memory: 64, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	stored, err := argon.Hash("password")
	if err != nil {
		t.Fatal(err)
	}
	var worker sync.WaitGroup
	var unblock sync.Once
	t.Cleanup(func() {
		unblock.Do(func() { close(h.release) })
		worker.Wait()
	})
	worker.Go(func() {
		if _, err := r.Hash("blocked"); err != nil {
			t.Errorf("blocking hash: %v", err)
		}
	})
	<-h.entered
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"hash", func() error { _, err := r.Hash("another"); return err }},
		{"current verification", func() error { return r.Compare("password", r.DummyHash()) }},
		{"legacy Argon2id with bcrypt current", func() error { return other.Compare("password", stored) }},
		{"unknown prefix", func() error { return r.Compare("password", "$unknown$hash") }},
		{"dummy verification", func() error { return r.BurnDummy("$malformed$") }},
		{"startup", func() error { _, err := NewWithWorkLimiter(h, l, hasher.New(4)); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); !errors.Is(err, domain.ErrPasswordWorkBusy) {
				t.Fatalf("overload = %v, want password_work_busy", err)
			}
		})
	}
	unblock.Do(func() { close(h.release) })
	worker.Wait()
	if err := other.Compare("password", stored); err != nil {
		t.Fatalf("legacy Argon2id after capacity release: %v", err)
	}
}

func TestRegistryCompareHoldsCapacityUntilFinished(t *testing.T) {
	l, err := hasher.NewWorkLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	h := &blockingWorkHasher{Hasher: argonFakeHasher{}, entered: make(chan struct{}), release: make(chan struct{})}
	r, err := NewWithWorkLimiter(h, l, hasher.New(4))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := h.Hasher.Hash("blocked")
	if err != nil {
		t.Fatal(err)
	}
	var worker sync.WaitGroup
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(h.release) }); worker.Wait() })
	worker.Go(func() {
		if err := r.Compare("blocked", stored); err != nil {
			t.Errorf("blocking comparison: %v", err)
		}
	})
	<-h.entered
	if _, err := r.Hash("password"); !errors.Is(err, domain.ErrPasswordWorkBusy) {
		t.Fatalf("hash during comparison = %v", err)
	}
	unblock.Do(func() { close(h.release) })
	worker.Wait()
	if _, err := r.Hash("password"); err != nil {
		t.Fatalf("hash after comparison = %v", err)
	}
}
