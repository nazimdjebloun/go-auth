package service

import (
	"context"
	"errors"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type transactionAuditFailure struct {
	calls int
}

func (p *transactionAuditFailure) Record(context.Context, audit.Event) error {
	p.calls++
	return errInjectedAuditFailure
}

func TestServiceConstructorsRequireTransactionManager(t *testing.T) {
	constructors := []struct {
		name string
		new  func(port.TxManager)
	}{
		{"auth", func(tx port.TxManager) {
			NewAuthService(tx, nil, nil, nil, nil, nil, nil, Config{}, nil, nil, nil)
		}},
		{"session", func(tx port.TxManager) {
			NewSessionService(tx, nil, nil, SessionConfig{})
		}},
		{"admin", func(tx port.TxManager) {
			NewAdminService(tx, nil, nil, nil, nil, nil, Config{}, nil)
		}},
		{"two factor", func(tx port.TxManager) {
			NewTwoFactorService(tx, nil, nil, nil, nil, nil, nil, Config{}, nil)
		}},
	}
	for _, constructor := range constructors {
		t.Run(constructor.name, func(t *testing.T) {
			for _, missing := range []struct {
				name string
				tx   port.TxManager
			}{
				{"nil", nil},
				{"typed nil", (*testutil.MockTxManager)(nil)},
			} {
				t.Run(missing.name, func(t *testing.T) {
					defer func() {
						if got := recover(); got != "goauth: service requires a non-nil transaction manager" {
							t.Fatalf("constructor panic = %v, want missing transaction manager", got)
						}
					}()
					constructor.new(missing.tx)
				})
			}
			t.Run("configured", func(t *testing.T) {
				constructor.new(&testutil.MockTxManager{})
			})
		})
	}
}

func TestRegisterAuditFailureRollsBackUserWithConstructorTransaction(t *testing.T) {
	users := testutil.NewMockUserRepo()
	cfg := defaultTestConfig()
	cfg.Audit = failingAuditPublisher{}
	svc := NewAuthService(&testutil.MockTxManager{}, users, nil, nil,
		&testutil.MockHasher{}, nil, nil, cfg, nil, nil, nil)
	ctx := context.Background()

	_, err := svc.Register(ctx, api.RegisterInput{
		Email: "register@example.com", Password: "Password1!", Name: "Test",
	})
	if !errors.Is(err, errInjectedAuditFailure) {
		t.Fatalf("Register error = %v, want audit failure", err)
	}
	user, err := users.GetByEmail(ctx, "register@example.com")
	if err != nil || user != nil {
		t.Fatalf("failed registration left a user: %+v, %v", user, err)
	}
}

func TestSessionAuditFailureRollsBackCreationWithConstructorTransaction(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	cfg := DefaultSessionConfig()
	cfg.Audit = failingAuditPublisher{}
	svc := NewSessionService(&testutil.MockTxManager{}, sessions, &testutil.MockTokenGen{Length: 32}, cfg)
	ctx := context.Background()

	_, err := svc.Create(ctx, "user-1", "", "")
	if !errors.Is(err, errInjectedAuditFailure) {
		t.Fatalf("Create error = %v, want audit failure", err)
	}
	live, err := sessions.ListAllByUserID(ctx, "user-1")
	if err != nil || len(live) != 0 {
		t.Fatalf("failed creation left sessions: %+v, %v", live, err)
	}
}

func TestLoginAuditFailureRollsBackNestedSessionWithConstructorTransactions(t *testing.T) {
	users := testutil.NewMockUserRepo()
	seedAuditPasswordUser(t, users, "user-1", "login@example.com", "Password1!")
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	tx := &testutil.MockTxManager{}
	sessionSvc := NewSessionService(tx, sessions, gen, DefaultSessionConfig())
	cfg := defaultTestConfig()
	auditFailure := &transactionAuditFailure{}
	cfg.Audit = auditFailure
	svc := NewAuthService(tx, users, sessions, nil, &testutil.MockHasher{}, gen, nil, cfg, sessionSvc, nil, nil)
	ctx := context.Background()

	_, err := svc.Login(ctx, api.LoginInput{Email: "login@example.com", Password: "Password1!"})
	if !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("Login error = %v, want internal error", err)
	}
	if auditFailure.calls != 1 {
		t.Fatalf("audit calls = %d, want failure after session creation", auditFailure.calls)
	}
	live, err := sessions.ListAllByUserID(ctx, "user-1")
	if err != nil || len(live) != 0 {
		t.Fatalf("failed login left sessions: %+v, %v", live, err)
	}
}
