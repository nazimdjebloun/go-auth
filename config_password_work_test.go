package goauth

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
)

type passwordWorkTestHasher struct {
	entered chan struct{}
	release chan struct{}
}

func (h *passwordWorkTestHasher) Hash(password string) (string, error) {
	if password == "blocked" {
		h.entered <- struct{}{}
		<-h.release
	}
	return "worktest$" + password, nil
}

func (*passwordWorkTestHasher) Compare(password, stored string) error {
	if stored != "worktest$"+password {
		return domain.ErrInvalidCredentials
	}
	return nil
}

func TestPasswordWorkConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name  string
		limit int
		want  int
	}{
		{"default", 0, 4},
		{"explicit", 2, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &passwordWorkTestHasher{entered: make(chan struct{}, tc.want), release: make(chan struct{})}
			cfg, err := NewConfig(append(validConfigOpts(), WithPasswordHashing(PasswordHashingConfig{Hasher: h, Concurrency: tc.limit}))...)
			if err != nil {
				t.Fatal(err)
			}
			pipeline, _, err := buildPasswordHasher(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			t.Cleanup(func() { close(h.release); workers.Wait() })
			for range tc.want {
				workers.Go(func() {
					if _, err := pipeline.Hash("blocked"); err != nil {
						t.Errorf("admitted hash: %v", err)
					}
				})
			}
			for range tc.want {
				<-h.entered
			}
			if err := pipeline.Compare("password", "worktest$password"); !errors.Is(err, domain.ErrPasswordWorkBusy) {
				t.Fatalf("configured cap was not enforced: %v", err)
			}
			// Reusing a Config creates independent capacity unless the caller
			// explicitly supplies a shared limiter.
			independent, _, err := buildPasswordHasher(cfg)
			if err != nil {
				t.Fatalf("independent startup: %v", err)
			}
			if _, err := independent.Hash("password"); err != nil {
				t.Fatalf("independent capacity: %v", err)
			}
			if cfg.passwordConcurrency != tc.limit {
				t.Fatal("configuration changed consumer intent")
			}
		})
	}
	for _, option := range []Option{
		WithPasswordHashing(PasswordHashingConfig{Concurrency: -1}),
		WithPasswordHashing(PasswordHashingConfig{WorkLimiter: &hasher.WorkLimiter{}}),
	} {
		if _, err := NewConfig(append(validConfigOpts(), option)...); err == nil {
			t.Fatal("invalid password-work configuration accepted")
		}
	}
	cfg, err := NewConfig(validConfigOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	WithPasswordHashing(PasswordHashingConfig{Concurrency: -1})(cfg)
	if a, err := New(cfg); err == nil {
		a.Close()
		t.Fatal("New accepted password concurrency mutated after validation")
	}
}

func TestPasswordWorkOverloadHTTPAndDirectCalls(t *testing.T) {
	l, err := hasher.NewWorkLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	f := newAppHTTPFixture(t, true, false, WithPasswordHashing(PasswordHashingConfig{BcryptCost: 4, Concurrency: 9, WorkLimiter: l}), WithRateLimitEnabled(false))
	created, err := f.a.Register(t.Context(), api.RegisterInput{Email: "work@example.com", Password: "Passw0rd!", Name: "Work"})
	if err != nil {
		t.Fatal(err)
	}
	other := newAuthWithHasherTestDB(t, newHasherTestDB(t), WithPasswordHashing(PasswordHashingConfig{BcryptCost: 4, WorkLimiter: l}))
	t.Cleanup(other.Close)
	if err := l.Do(func() error {
		for _, email := range []string{created.User.Email, "missing@example.com"} {
			for _, path := range []string{"/auth/login", "/auth/admin/login"} {
				w := f.request(t, "POST", path, `{"email":"`+email+`","password":"WrongPass1!"}`, "", http.StatusServiceUnavailable)
				var body map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if len(body) != 2 || body["error"] != "password_work_busy" || body["message"] != domain.ErrPasswordWorkBusy.Message {
					t.Fatalf("unexpected overload envelope: %s", w.Body.String())
				}
			}
		}
		if _, err := f.a.Register(t.Context(), api.RegisterInput{Email: "new-work@example.com", Password: "Passw0rd!", Name: "New"}); !errors.Is(err, domain.ErrPasswordWorkBusy) {
			t.Fatalf("direct registration overload: %v", err)
		}
		if _, err := other.Login(t.Context(), api.LoginInput{Email: "missing@example.com", Password: "WrongPass1!"}); !errors.Is(err, domain.ErrPasswordWorkBusy) {
			t.Fatalf("shared Auth overload: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.Login(t.Context(), api.LoginInput{Email: created.User.Email, Password: "Passw0rd!"}); err != nil {
		t.Fatalf("login after overload: %v", err)
	}
	if _, err := f.a.Register(t.Context(), api.RegisterInput{Email: "new-work@example.com", Password: "Passw0rd!", Name: "New"}); err != nil {
		t.Fatalf("registration retry after overload: %v", err)
	}
}
