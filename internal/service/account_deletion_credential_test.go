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

func TestAccountDeletionRechecksPasswordIdentity(t *testing.T) {
	for _, action := range []string{"change", "reset", "ban", "unchanged"} {
		t.Run(action, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			seedDeletionOrg(t, f, "00000000-0000-4000-8000-000000000091", 2)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			barrier := &loginCompareBarrier{Hasher: f.hasher, checked: make(chan struct{}), release: make(chan struct{})}
			defer func() {
				select {
				case <-barrier.release:
				default:
					close(barrier.release)
				}
			}()
			pub := &testutil.MockAuditPublisher{}
			cfg := defaultTestConfig()
			cfg.Audit = pub
			svc := NewAuthService(f.db, f.users, f.sessions, f.tokens, barrier, nil, nil, cfg, nil, nil, nil)
			svc.AttachAccountDeletion(deletionCoordinator(f))
			done := make(chan error, 1)
			go func() {
				done <- svc.DeleteAccount(ctx, api.DeleteAccountInput{UserID: f.userID, Password: "OldPass1!"})
			}()
			select {
			case <-barrier.checked:
			case <-ctx.Done():
				t.Fatal("deletion did not reach password comparison")
			}
			passwords := f.passwordService(f.hasher, f.sessions)
			var err error
			var want error
			switch action {
			case "change":
				err = passwords.ChangePassword(ctx, api.ChangePasswordInput{UserID: f.userID, OldPassword: "OldPass1!", NewPassword: "OwnerNew2!"})
				want = domain.ErrInvalidCredentials
			case "reset":
				err = passwords.ResetPassword(ctx, api.ResetPasswordInput{Code: f.code, NewPassword: "OwnerNew2!"})
				want = domain.ErrInvalidCredentials
			case "ban":
				now := time.Now().UTC()
				err = f.users.SetBanStatus(ctx, f.userID, true, &now, now)
				want = domain.ErrUserBanned
			}
			close(barrier.release)
			deletionErr := <-done
			if err != nil {
				t.Fatal(err)
			}
			if !errors.Is(deletionErr, want) {
				t.Fatalf("deletion after %s=%v, want %v", action, deletionErr, want)
			}
			user, err := f.users.GetByID(ctx, f.userID)
			if err != nil {
				t.Fatal(err)
			}
			if action == "unchanged" {
				if user != nil || findEvent(pub.Events, audit.EventAccountDeleted) == nil {
					t.Fatal("valid deletion did not delete and record")
				}
				return
			}
			if user == nil {
				t.Fatal("stale credential deleted the account")
			}
			if action != "ban" && f.hasher.Compare("OwnerNew2!", *user.PasswordHash) != nil {
				t.Fatal("deletion changed the rotated password")
			}
			deletionCount(t, f, "SELECT member_count FROM organizations", 2)
			deletionCount(t, f, "SELECT owner_count FROM organizations", 2)
			if len(pub.Events) != 0 {
				t.Fatal("rejected deletion published an audit event")
			}
		})
	}
}
