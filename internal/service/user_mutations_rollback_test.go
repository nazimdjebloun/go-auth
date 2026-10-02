package service

import (
	"context"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

func TestUserMutations_VerificationRollback(t *testing.T) {
	for _, scenario := range []string{"changed email", "write failure"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			ctx := context.Background()
			cfg := defaultTestConfig()
			cfg.OTPPepper = []byte("mutation-test-pepper")
			u, err := f.users.GetByID(ctx, f.userID)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.db.ExecContext(ctx, "UPDATE users SET is_verified=false, verified_at=NULL WHERE id=$1", f.userID); err != nil {
				t.Fatal(err)
			}
			const code = "rollback-verification"
			if err := f.tokens.Create(ctx, &domain.VerificationToken{ID: "00000000-0000-4000-8000-000000000081", UserID: &f.userID, Email: u.Email, TokenHash: hashOTP(code, cfg.OTPPepper), Type: domain.TokenVerifyEmail, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			users := &mutationReadHook{UserRepository: f.users}
			users.afterRead = func() {
				var err error
				if scenario == "write failure" {
					testdb.FailWrites(t, f.db.DB, "reject_verification", "users", "UPDATE", "")
				} else {
					_, err = f.db.ExecContext(ctx, "UPDATE users SET email=$1 WHERE id=$2", "changed@example.com", f.userID)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			svc := NewVerificationService(users, f.tokens, nil, nil, f.db, cfg)
			verified, err := svc.VerifyEmail(ctx, code)
			want := "code_invalid"
			if scenario == "write failure" {
				want = "internal_error"
			}
			if verified != nil || authErrCode(err) != want {
				t.Fatalf("result=%v err=%v, want %s", verified, err, want)
			}
			stored, err := f.tokens.GetByHash(ctx, hashOTP(code, cfg.OTPPepper))
			if err != nil {
				t.Fatal(err)
			}
			if stored == nil || stored.UsedAt != nil {
				t.Fatal("failed verification consumed token")
			}
			u, err = f.users.GetByID(ctx, f.userID)
			if err != nil {
				t.Fatal(err)
			}
			if u.IsVerified || u.VerifiedAt != nil {
				t.Fatal("failed verification changed status")
			}
			if scenario == "changed email" && u.Email != "changed@example.com" {
				t.Fatal("stale email restored")
			}
		})
	}
}
