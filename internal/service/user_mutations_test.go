package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/port"
)

type mutationReadHook struct {
	*sqlstore.UserRepository
	afterRead func()
}

func (r *mutationReadHook) GetByID(ctx context.Context, id string) (*domain.User, error) {
	u, err := r.UserRepository.GetByID(ctx, id)
	if err == nil && r.afterRead != nil {
		hook := r.afterRead
		r.afterRead = nil
		hook()
	}
	return u, err
}

func TestUserMutations_NamePreservesConcurrentIdentity(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	ctx := context.Background()
	users := &mutationReadHook{UserRepository: f.users}
	users.afterRead = func() {
		_, err := f.db.ExecContext(ctx, "UPDATE users SET email=$1, is_verified=false, verified_at=NULL WHERE id=$2", "changed@example.com", f.userID)
		if err != nil {
			t.Fatal(err)
		}
	}
	svc := &AuthService{users: users, log: slog.Default()}
	if err := svc.ChangeName(ctx, api.ChangeNameInput{
		UserID: f.userID,
		Name:   "New name",
	}); err != nil {
		t.Fatal(err)
	}
	u, err := f.users.GetByID(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "New name" || u.Email != "changed@example.com" || u.IsVerified || u.VerifiedAt != nil {
		t.Fatalf("name update overwrote unrelated identity fields: %+v", u)
	}
}

func TestUserMutations_VerificationPreservesConcurrentName(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	ctx := context.Background()
	cfg := defaultTestConfig()
	cfg.OTPPepper = []byte("mutation-test-pepper")
	u, err := f.users.GetByID(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	const code = "verify-mutation"
	if err := f.tokens.Create(ctx, &domain.VerificationToken{ID: "00000000-0000-4000-8000-000000000080", UserID: &f.userID, Email: u.Email, TokenHash: hashOTP(code, cfg.OTPPepper), Type: domain.TokenVerifyEmail, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	users := &mutationReadHook{UserRepository: f.users}
	users.afterRead = func() {
		if _, err := f.db.ExecContext(ctx, "UPDATE users SET name=$1 WHERE id=$2", "Concurrent name", f.userID); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewVerificationService(users, f.tokens, nil, nil, f.db, cfg)
	if _, err := svc.VerifyEmail(ctx, code); err != nil {
		t.Fatal(err)
	}
	u, err = f.users.GetByID(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "Concurrent name" || !u.IsVerified {
		t.Fatalf("verification overwrote profile: %+v", u)
	}
}

var _ port.UserRepository = (*mutationReadHook)(nil)
