package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestAccountDeletion_CodeClaimAndRollback(t *testing.T) {
	for _, name := range []string{"success", "last owner", "last admin", "late failure", "used code", "expired code", "wrong code"} {
		t.Run(name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			seedDeletionOrg(t, f, "00000000-0000-4000-8000-000000000091", 2)
			cfg := defaultTestConfig()
			cfg.OTPPepper = []byte("account-deletion-tests-pepper-32bytes")
			pub := &testutil.MockAuditPublisher{}
			cfg.Audit = pub
			deletionExec(t, f, `UPDATE users SET password_hash=NULL WHERE id=$1`, f.userID)
			deletionExec(t, f, `UPDATE verification_tokens SET type=$1,token_hash=$2 WHERE id=$3`, domain.TokenDeleteAccount, hashOTP("ABCDEFGH", cfg.OTPPepper), f.tokenID)
			wantOwners := 2
			var want error
			code := "ABCDEFGH"
			switch name {
			case "last owner":
				deletionExec(t, f, `UPDATE organization_members SET role='member' WHERE user_id='00000000-0000-4000-8000-000000000090'`)
				deletionExec(t, f, `UPDATE organizations SET owner_count=1`)
				wantOwners = 1
				want = domain.ErrCannotRemoveLastOwner
			case "last admin":
				deletionExec(t, f, `UPDATE users SET role='admin' WHERE id=$1`, f.userID)
				want = domain.ErrCannotDeleteLastAdmin
			case "late failure":
				deletionExec(t, f, `CREATE TRIGGER fail_delete BEFORE DELETE ON users BEGIN SELECT RAISE(ABORT,'late delete failure'); END`)
				want = domain.ErrInternal
			case "used code":
				deletionExec(t, f, `UPDATE verification_tokens SET used_at=$1`, time.Now().UTC())
				want = domain.ErrDeleteCodeAlreadyUsed
			case "expired code":
				deletionExec(t, f, `UPDATE verification_tokens SET expires_at=$1`, time.Now().UTC().Add(-time.Hour))
				want = domain.ErrDeleteCodeExpired
			case "wrong code":
				code = "WRONG123"
				want = domain.ErrDeleteCodeInvalid
			}
			svc := NewAuthService(f.db, f.users, f.sessions, f.tokens, f.hasher, nil, nil, cfg, nil, nil, nil)
			svc.AttachAccountDeletion(deletionCoordinator(f))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := svc.ConfirmDeleteAccount(ctx, api.ConfirmDeleteAccountInput{UserID: f.userID, Code: code})
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
			if name == "success" {
				deletionCount(t, f, "SELECT COUNT(*) FROM sessions", 0)
				deletionCount(t, f, "SELECT COUNT(*) FROM verification_tokens", 0)
				deletionCount(t, f, "SELECT member_count FROM organizations", 1)
				if findEvent(pub.Events, audit.EventAccountDeleted) == nil {
					t.Fatal("successful deletion missing audit event")
				}
			} else {
				if len(pub.Events) != 0 {
					t.Fatal("failed deletion published audit event")
				}
				if name == "used code" {
					token, err := f.tokens.GetByID(ctx, f.tokenID)
					if err != nil || token == nil || token.UsedAt == nil {
						t.Fatal("used token state changed")
					}
					// Reset only for the common unchanged-state assertion below.
					deletionExec(t, f, `UPDATE verification_tokens SET used_at=NULL`)
				}
				assertDeletionRolledBack(t, f, wantOwners)
			}
		})
	}
}

func TestAccountDeletion_PasswordAndAdminPaths(t *testing.T) {
	for _, path := range []string{"password", "admin"} {
		t.Run(path, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			seedDeletionOrg(t, f, "00000000-0000-4000-8000-000000000091", 1)
			cfg := defaultTestConfig()
			pub := &testutil.MockAuditPublisher{}
			cfg.Audit = pub
			var err error
			if path == "password" {
				svc := NewAuthService(f.db, f.users, f.sessions, f.tokens, f.hasher, nil, nil, cfg, nil, nil, nil)
				svc.AttachAccountDeletion(deletionCoordinator(f))
				err = svc.DeleteAccount(context.Background(), api.DeleteAccountInput{
					UserID:   f.userID,
					Password: "OldPass1!",
				})
			} else {
				deletionExec(t, f, `UPDATE users SET role='admin' WHERE id='00000000-0000-4000-8000-000000000090'`)
				svc := NewAdminService(f.db, f.users, f.sessions, nil, nil, f.hasher, cfg, nil)
				svc.AttachAccountDeletion(deletionCoordinator(f))
				err = svc.DeleteUser(context.Background(), api.DeleteUserInput{ActorID: "00000000-0000-4000-8000-000000000090", UserID: f.userID})
			}
			if !errors.Is(err, domain.ErrCannotRemoveLastOwner) {
				t.Fatalf("got %v", err)
			}
			assertDeletionRolledBack(t, f, 1)
			if len(pub.Events) != 0 {
				t.Fatal("failed deletion published audit event")
			}
		})
	}
}
