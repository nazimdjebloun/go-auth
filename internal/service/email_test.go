package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type emailFixture struct {
	*passwordTransactionFixture
	svc   *EmailService
	mail  *testutil.MockMailer
	actor api.EmailChangeActor
	clock time.Time
}

func newEmailFixture(t *testing.T) *emailFixture {
	t.Helper()
	f := newPasswordTransactionFixture(t)
	cfg := defaultTestConfig()
	cfg.EmailChanges = sqlstore.NewEmailChangeRepository(f.db)
	cfg.DisableAdminTwoFactor = true
	mail := &testutil.MockMailer{}
	sessions := NewSessionService(f.db, f.sessions, &testutil.MockTokenGen{Length: 32}, DefaultSessionConfig())
	two := NewTwoFactorService(f.db, f.users, f.sessions, f.tokens, f.hasher, mail, nil, cfg, sessions)
	svc := NewEmailService(f.db, f.users, f.sessions, sqlstore.NewEmailChangeRepository(f.db), sqlstore.NewRecoveryRepository(f.db), sessions, two, f.hasher, mail, cfg)
	v := &emailFixture{passwordTransactionFixture: f, svc: svc, mail: mail, actor: api.EmailChangeActor{UserID: f.userID, SessionID: "00000000-0000-4000-8000-000000000012"}, clock: time.Now().UTC().Truncate(time.Microsecond)}
	svc.now = func() time.Time { return v.clock }
	return v
}

func (f *emailFixture) request(t *testing.T) *api.EmailChangeResult {
	t.Helper()
	r, err := f.svc.RequestEmailChange(t.Context(), api.RequestEmailChangeInput{Actor: f.actor, NewEmail: " NEW@Example.com ", Password: "OldPass1!"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *emailFixture) proof(t *testing.T, r *api.EmailChangeResult) api.ConfirmEmailChangeInput {
	t.Helper()
	codes := map[string]string{}
	for _, m := range f.mail.Calls {
		for _, line := range strings.Split(m.Text, "\n") {
			if len(strings.TrimSpace(line)) == 8 {
				codes[m.To] = strings.TrimSpace(line)
			}
		}
	}
	if codes["password-transaction@example.com"] == "" || codes["new@example.com"] == "" {
		t.Fatal("missing dual mailbox proof")
	}
	return api.ConfirmEmailChangeInput{Actor: f.actor, RequestID: r.RequestID, CurrentEmailCode: codes["password-transaction@example.com"], NewEmailCode: codes["new@example.com"]}
}

func (f *emailFixture) stored(t *testing.T) *port.EmailChangeRequest {
	t.Helper()
	var v *port.EmailChangeRequest
	if err := f.db.WithTx(t.Context(), func(ctx context.Context) error {
		if _, err := f.users.GetByIDForUpdate(ctx, f.userID); err != nil {
			return err
		}
		var err error
		v, err = f.svc.store.Load(ctx, f.userID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEmailChangeCompletesAtomicallyAndQueuesNotices(t *testing.T) {
	f := newEmailFixture(t)
	r := f.request(t)
	input := f.proof(t, r)
	before, _ := f.users.GetByID(t.Context(), f.userID)
	if before.Email != "password-transaction@example.com" {
		t.Fatal("email changed before proof")
	}
	stored := f.stored(t)
	if strings.Contains(stored.CurrentCodeHash, input.CurrentEmailCode) || strings.Contains(stored.NewCodeHash, input.NewEmailCode) {
		t.Fatal("raw code persisted")
	}
	if err := f.svc.ConfirmEmailChange(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	u, err := f.users.GetByID(t.Context(), f.userID)
	if err != nil || u.Email != "new@example.com" || !u.IsVerified || u.VerifiedAt == nil || u.Name != before.Name || *u.PasswordHash != *before.PasswordHash {
		t.Fatalf("unexpected identity: %+v %v", u, err)
	}
	for _, table := range []string{"sessions", "verification_tokens"} {
		var n int
		if err := f.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM "+table+" WHERE user_id=$1", f.userID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s not revoked: %d %v", table, n, err)
		}
	}
	var n int
	if err := f.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM recovery_requests WHERE kind='email_changed'").Scan(&n); err != nil || n != 2 {
		t.Fatalf("missing notices: %d %v", n, err)
	}
	if f.mail.SentCount() != 2 {
		t.Fatal("completion notices must not use SMTP inside transaction")
	}
	pass := NewPasswordService(f.users, f.tokens, f.hasher, &testutil.MockTokenGen{Length: 32}, f.mail, f.sessions, f.db, f.svc.config)
	verify := NewVerificationService(f.users, f.tokens, nil, f.mail, f.db, f.svc.config)
	worker := NewRecoveryWorker(sqlstore.NewRecoveryRepository(f.db), pass, verify, nil)
	for range 2 {
		if processed, err := worker.ProcessOne(t.Context()); err != nil || !processed {
			t.Fatalf("notice delivery: %v %v", processed, err)
		}
	}
	if f.mail.SentCount() != 4 {
		t.Fatal("missing completed notices")
	}
	if err := f.svc.ConfirmEmailChange(t.Context(), input); err == nil {
		t.Fatal("replay succeeded")
	}
}

func TestEmailChangeRejectsInvalidProofAndIdentity(t *testing.T) {
	for _, name := range []string{"wrong current", "wrong new", "swapped", "wrong id", "other session", "other context", "expired", "pepper rotation", "password replaced", "email replaced", "MFA changed", "revoked session", "banned", "required verification", "required MFA", "new admin requirement"} {
		t.Run(name, func(t *testing.T) {
			f := newEmailFixture(t)
			r := f.request(t)
			input := f.proof(t, r)
			ctx := t.Context()
			query := ""
			args := []any{}
			switch name {
			case "wrong current":
				input.CurrentEmailCode = "INVALID!"
			case "wrong new":
				input.NewEmailCode = "INVALID!"
			case "swapped":
				input.CurrentEmailCode, input.NewEmailCode = input.NewEmailCode, input.CurrentEmailCode
			case "wrong id":
				input.RequestID = uuid.NewString()
			case "other session":
				input.Actor.SessionID = uuid.NewString()
			case "other context":
				ctx = sessioncontext.With(ctx, sessioncontext.Admin)
			case "expired":
				f.clock = r.ExpiresAt
			case "pepper rotation":
				f.svc.config.SecretRotatedAt = f.clock.Add(time.Second)
			case "password replaced":
				query = "UPDATE users SET password_hash=$1 WHERE id=$2"
				args = []any{"changed-hash", f.userID}
			case "email replaced":
				query = "UPDATE users SET email=$1 WHERE id=$2"
				args = []any{"other@example.com", f.userID}
			case "MFA changed":
				query = "UPDATE users SET two_factor_enabled=true WHERE id=$1"
				args = []any{f.userID}
			case "revoked session":
				query = "DELETE FROM sessions WHERE user_id=$1"
				args = []any{f.userID}
			case "banned":
				query = "UPDATE users SET is_banned=true WHERE id=$1"
				args = []any{f.userID}
			case "required verification":
				query = "UPDATE users SET is_verified=false WHERE id=$1"
				args = []any{f.userID}
				f.svc.sessionSvc.config.RequireEmailVerification = true
			case "required MFA":
				f.svc.twoFactor.config.RequireEmail2FA = true
			case "new admin requirement":
				query = "UPDATE users SET role='admin' WHERE id=$1"
				args = []any{f.userID}
				f.svc.twoFactor.config.DisableAdminTwoFactor = false
			}
			if query != "" {
				if _, err := f.db.ExecContext(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.svc.ConfirmEmailChange(ctx, input); err == nil {
				t.Fatal("invalid proof accepted")
			}
			u, err := f.users.GetByID(t.Context(), f.userID)
			if err != nil || u.Email == "new@example.com" {
				t.Fatal("invalid proof changed identity")
			}
		})
	}
}

func TestEmailChangeAttemptCapSurvivesResend(t *testing.T) {
	f := newEmailFixture(t)
	r := f.request(t)
	input := f.proof(t, r)
	bad := input
	bad.NewEmailCode = "wrong"
	for range 4 {
		if !errors.Is(f.svc.ConfirmEmailChange(t.Context(), bad), domain.ErrEmailChangeInvalid) {
			t.Fatal("bad proof accepted")
		}
	}
	f.clock = f.clock.Add(time.Minute)
	again, err := f.svc.ResendEmailChange(t.Context(), api.ResendEmailChangeInput{Actor: f.actor, RequestID: r.RequestID, Destination: "new"})
	if err != nil || !again.ExpiresAt.Equal(r.ExpiresAt) {
		t.Fatalf("resend: %+v %v", again, err)
	}
	if !errors.Is(f.svc.ConfirmEmailChange(t.Context(), input), domain.ErrEmailChangeInvalid) {
		t.Fatal("old new-address code remained usable")
	}
	if f.stored(t).Attempts != 5 {
		t.Fatal("resend reset guess budget")
	}
	if v := f.stored(t); v.CurrentCodeHash != "" || v.NewCodeHash != "" {
		t.Fatal("exhausted proofs retained their hashes")
	}
	if !errors.Is(f.svc.ConfirmEmailChange(t.Context(), f.proof(t, again)), domain.ErrEmailChangeInvalid) {
		t.Fatal("correct proof bypassed exhausted cap")
	}
}

func TestEmailChangeExpiredProofCleanupPreservesBudget(t *testing.T) {
	f := newEmailFixture(t)
	r := f.request(t)
	proof := f.proof(t, r)
	before := f.stored(t)
	maintenance := sqlstore.NewRecoveryRepository(f.db)
	if err := maintenance.Prune(t.Context(), r.ExpiresAt.Add(-time.Microsecond)); err != nil {
		t.Fatal(err)
	}
	if v := f.stored(t); v.CurrentCodeHash != before.CurrentCodeHash || v.NewCodeHash != before.NewCodeHash {
		t.Fatal("maintenance erased a live proof")
	}
	for range 2 {
		if err := maintenance.Prune(t.Context(), r.ExpiresAt); err != nil {
			t.Fatal(err)
		}
	}
	after := f.stored(t)
	if after.CurrentCodeHash != "" || after.NewCodeHash != "" || after.Starts != before.Starts || !after.BudgetStartedAt.Equal(before.BudgetStartedAt) || after.Status != before.Status {
		t.Fatal("expiry cleanup retained proofs or changed the budget/status")
	}
	f.clock = r.ExpiresAt
	if err := f.svc.ConfirmEmailChange(t.Context(), proof); !errors.Is(err, domain.ErrEmailChangeExpired) {
		t.Fatalf("expired proof error: %v", err)
	}
	if err := f.svc.CancelEmailChange(t.Context(), api.CancelEmailChangeInput{Actor: f.actor, RequestID: r.RequestID}); err != nil {
		t.Fatal("expiry cleanup prevented cancellation", err)
	}
	replacement := f.request(t)
	if err := maintenance.Prune(t.Context(), r.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.ConfirmEmailChange(t.Context(), f.proof(t, replacement)); err != nil {
		t.Fatal("cleanup invalidated a live replacement", err)
	}
}

func TestEmailChangeConcurrentExpiryCleanupAndReplacement(t *testing.T) {
	f := newEmailFixture(t)
	old := f.request(t)
	f.clock = old.ExpiresAt
	var replacement *api.EmailChangeResult
	var requestErr, cleanupErr error
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Go(func() {
		<-start
		replacement, requestErr = f.svc.RequestEmailChange(t.Context(), api.RequestEmailChangeInput{Actor: f.actor, NewEmail: "new@example.com", Password: "OldPass1!"})
	})
	wg.Go(func() {
		<-start
		cleanupErr = sqlstore.NewRecoveryRepository(f.db).Prune(t.Context(), old.ExpiresAt)
	})
	close(start)
	wg.Wait()
	if requestErr != nil || cleanupErr != nil {
		t.Fatalf("replacement=%v cleanup=%v", requestErr, cleanupErr)
	}
	v := f.stored(t)
	if v.ID != replacement.RequestID || v.Starts != 2 || v.CurrentCodeHash == "" || v.NewCodeHash == "" {
		t.Fatal("expiry maintenance erased a replacement or changed its start budget")
	}
	if err := f.svc.ConfirmEmailChange(t.Context(), f.proof(t, replacement)); err != nil {
		t.Fatal(err)
	}
}

func TestEmailChangeResendCooldownRotationAndCap(t *testing.T) {
	for _, destination := range []string{"current", "new"} {
		t.Run(destination, func(t *testing.T) {
			f := newEmailFixture(t)
			r := f.request(t)
			input := api.ResendEmailChangeInput{Actor: f.actor, RequestID: r.RequestID, Destination: destination}
			if _, err := f.svc.ResendEmailChange(t.Context(), input); !errors.Is(err, domain.ErrRateLimitExceeded) {
				t.Fatal("missing cooldown")
			}
			for range 3 {
				f.clock = f.clock.Add(time.Minute)
				if _, err := f.svc.ResendEmailChange(t.Context(), input); err != nil {
					t.Fatal(err)
				}
			}
			f.clock = f.clock.Add(time.Minute)
			if _, err := f.svc.ResendEmailChange(t.Context(), input); !errors.Is(err, domain.ErrRateLimitExceeded) {
				t.Fatal("missing resend cap")
			}
			if err := f.svc.ConfirmEmailChange(t.Context(), f.proof(t, r)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEmailChangeReplacementCancelAndStartBudget(t *testing.T) {
	f := newEmailFixture(t)
	first := f.request(t)
	old := f.proof(t, first)
	if err := f.svc.CancelEmailChange(t.Context(), api.CancelEmailChangeInput{Actor: f.actor, RequestID: first.RequestID}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(f.svc.ConfirmEmailChange(t.Context(), old), domain.ErrEmailChangeInvalid) {
		t.Fatal("cancelled request accepted")
	}
	second := f.request(t)
	staleVersion := *f.stored(t)
	third := f.request(t)
	if first.RequestID == second.RequestID || second.RequestID == third.RequestID {
		t.Fatal("replacement reused ID")
	}
	if err := f.svc.store.DiscardVersion(t.Context(), &staleVersion); err != nil {
		t.Fatal(err)
	}
	if f.stored(t).Status != "pending" {
		t.Fatal("stale delivery cleanup cancelled replacement")
	}
	if _, err := f.svc.RequestEmailChange(t.Context(), api.RequestEmailChangeInput{Actor: f.actor, NewEmail: "new@example.com", Password: "OldPass1!"}); !errors.Is(err, domain.ErrRateLimitExceeded) {
		t.Fatal("replacement reset hourly start budget")
	}
	if err := f.svc.ConfirmEmailChange(t.Context(), old); !errors.Is(err, domain.ErrEmailChangeInvalid) {
		t.Fatal("replaced request accepted")
	}
	if err := f.svc.ConfirmEmailChange(t.Context(), f.proof(t, third)); err != nil {
		t.Fatal(err)
	}
}

type failingEmailSessions struct{ emailSessions }

func (f failingEmailSessions) DeleteAllForUser(context.Context, string) error {
	return errors.New("injected revocation failure")
}

type failingEmailNotices struct{}

func (failingEmailNotices) Enqueue(context.Context, port.RecoveryKind, string) error {
	return errors.New("injected notice failure")
}

type failingEmailAudit struct{}

func (failingEmailAudit) Record(context.Context, audit.Event) error {
	return errors.New("injected audit failure")
}

func TestEmailChangeRollback(t *testing.T) {
	for _, name := range []string{"revocation", "notifications", "request consume", "token deletion", "audit", "outer transaction"} {
		t.Run(name, func(t *testing.T) {
			f := newEmailFixture(t)
			r := f.request(t)
			input := f.proof(t, r)
			switch name {
			case "revocation":
				f.svc.sessions = failingEmailSessions{f.sessions}
			case "notifications":
				f.svc.notices = failingEmailNotices{}
			case "request consume":
				testdb.FailWrites(t, f.db.DB, "email_fail_request", "email_change_requests", "UPDATE", "")
			case "token deletion":
				testdb.FailWrites(t, f.db.DB, "email_fail_tokens", "verification_tokens", "DELETE", "")
			case "audit":
				f.svc.config.Audit = failingEmailAudit{}
			}
			var err error
			if name == "outer transaction" {
				err = f.db.WithTx(t.Context(), func(ctx context.Context) error {
					if err := f.svc.ConfirmEmailChange(ctx, input); err != nil {
						return err
					}
					return errors.New("outer rollback")
				})
			} else {
				err = f.svc.ConfirmEmailChange(t.Context(), input)
			}
			if err == nil {
				t.Fatal("injected failure ignored")
			}
			u, e := f.users.GetByID(t.Context(), f.userID)
			if e != nil || u.Email != "password-transaction@example.com" {
				t.Fatal("failed transaction changed email")
			}
			if f.stored(t).Status != "pending" {
				t.Fatal("failed transaction consumed proof")
			}
			if session, e := f.sessions.GetByID(t.Context(), f.actor.SessionID); e != nil || session == nil {
				t.Fatal("failed transaction lost session")
			}
			if token, e := f.tokens.GetByID(t.Context(), f.tokenID); e != nil || token == nil {
				t.Fatal("failed transaction lost reset token")
			}
			var n int
			if e := f.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM recovery_requests").Scan(&n); e != nil || n != 0 {
				t.Fatal("failed transaction queued notice")
			}
		})
	}
}

func TestEmailChangeFailedDeliveryCannotAuthorize(t *testing.T) {
	for _, destination := range []string{"current", "new"} {
		t.Run(destination, func(t *testing.T) {
			f := newEmailFixture(t)
			f.mail.SendFn = func(_ context.Context, to, _, _, _ string) error {
				if (destination == "current" && to == "password-transaction@example.com") || (destination == "new" && to == "new@example.com") {
					return errors.New("delivery failed")
				}
				return nil
			}
			if result, err := f.svc.RequestEmailChange(t.Context(), api.RequestEmailChangeInput{Actor: f.actor, NewEmail: "new@example.com", Password: "OldPass1!"}); result != nil || !errors.Is(err, domain.ErrEmailFailed) {
				t.Fatalf("delivery failure: %v %v", result, err)
			}
			v := f.stored(t)
			if v.Status != "cancelled" || v.CurrentCodeHash != "" || v.NewCodeHash != "" {
				t.Fatal("undelivered proof usable")
			}
			if v.Starts != 1 {
				t.Fatal("failed delivery refunded abuse budget")
			}
		})
	}
}

func TestEmailChangeDuplicateAddressAndConcurrentConfirm(t *testing.T) {
	t.Run("duplicate only disclosed after proof", func(t *testing.T) {
		f := newEmailFixture(t)
		if err := f.users.Create(t.Context(), &domain.User{ID: uuid.NewString(), Email: "new@example.com", Role: domain.RoleUser, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		r := f.request(t)
		if err := f.svc.ConfirmEmailChange(t.Context(), f.proof(t, r)); !errors.Is(err, domain.ErrEmailChangeUnavailable) {
			t.Fatalf("duplicate: %v", err)
		}
		if f.stored(t).Status != "pending" {
			t.Fatal("duplicate conflict consumed proof")
		}
	})
	t.Run("exactly one completion", func(t *testing.T) {
		f := newEmailFixture(t)
		r := f.request(t)
		input := f.proof(t, r)
		start := make(chan struct{})
		results := make(chan error, 8)
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() { <-start; results <- f.svc.ConfirmEmailChange(t.Context(), input) })
		}
		close(start)
		wg.Wait()
		close(results)
		wins := 0
		for err := range results {
			if err == nil {
				wins++
			}
		}
		if wins != 1 {
			t.Fatalf("completion winners=%d", wins)
		}
		var n int
		if err := f.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM recovery_requests").Scan(&n); err != nil || n != 2 {
			t.Fatalf("duplicate notices: %d %v", n, err)
		}
	})
}

func TestEmailChangePasswordlessAndPasswordAuthenticationDisabled(t *testing.T) {
	for _, name := range []string{"passwordless", "password authentication disabled"} {
		t.Run(name, func(t *testing.T) {
			f := newEmailFixture(t)
			if name == "passwordless" {
				if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET password_hash=NULL WHERE id=$1", f.userID); err != nil {
					t.Fatal(err)
				}
			} else {
				f.svc.config.PasswordAuthenticationDisabled = true
			}
			r, err := f.svc.RequestEmailChange(t.Context(), api.RequestEmailChangeInput{Actor: f.actor, NewEmail: "new@example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if err := f.svc.ConfirmEmailChange(t.Context(), f.proof(t, r)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEmailChangeExpiryRoundTripsWithoutExtension(t *testing.T) {
	f := newEmailFixture(t)
	// Real clocks include nanoseconds; the SQL slot persists microseconds.
	f.clock = time.Now().UTC()
	r := f.request(t)
	if !r.ExpiresAt.Equal(f.stored(t).ExpiresAt) {
		t.Fatal("response expiry differs from persisted expiry")
	}
	f.clock = f.clock.Add(time.Minute)
	again, err := f.svc.ResendEmailChange(t.Context(), api.ResendEmailChangeInput{Actor: f.actor, RequestID: r.RequestID, Destination: "new"})
	if err != nil || !again.ExpiresAt.Equal(r.ExpiresAt) {
		t.Fatalf("resend changed expiry: %v", err)
	}
}

func TestEmailChangeConcurrentPasswordResetHasOneWinner(t *testing.T) {
	f := newEmailFixture(t)
	r := f.request(t)
	input := f.proof(t, r)
	reset := f.passwordService(f.hasher, f.sessions)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Go(func() { <-start; results <- f.svc.ConfirmEmailChange(t.Context(), input) })
	wg.Go(func() {
		<-start
		results <- reset.ResetPassword(t.Context(), api.ResetPasswordInput{Code: f.code, NewPassword: "NewPass1!"})
	})
	close(start)
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("credential race winners=%d", wins)
	}
	u, err := f.users.GetByID(t.Context(), f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Email == "new@example.com" {
		if *u.PasswordHash != f.oldHash {
			t.Fatal("stale reset changed password after email change")
		}
	} else if f.hasher.Compare("NewPass1!", *u.PasswordHash) != nil {
		t.Fatal("reset winner lost its password")
	}
}

func TestEmailChangeSettingsCannotReviveProofs(t *testing.T) {
	for _, name := range []string{"same deterministic password", "MFA toggled back"} {
		t.Run(name, func(t *testing.T) {
			f := newEmailFixture(t)
			r := f.request(t)
			proof := f.proof(t, r)
			if name == "same deterministic password" {
				// MySQL stores updated_at at second precision. Make the write
				// observable even when this deterministic hasher returns the
				// existing hash; otherwise affected-rows reports a no-op conflict.
				if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET updated_at=$1 WHERE id=$2", time.Now().UTC().Add(-time.Hour), f.userID); err != nil {
					t.Fatal(err)
				}
				password := NewPasswordService(f.users, f.tokens, f.hasher, &testutil.MockTokenGen{Length: 32}, f.mail, f.sessions, f.db, f.svc.config)
				if err := password.ChangePassword(t.Context(), api.ChangePasswordInput{UserID: f.userID, OldPassword: "OldPass1!", NewPassword: "OldPass1!", ExceptSessionID: f.actor.SessionID}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := f.svc.twoFactor.Enable(t.Context(), api.TwoFactorEnableInput{UserID: f.userID, Password: "OldPass1!", CallerSessionID: f.actor.SessionID, KeepOtherSessions: true}); err != nil {
					t.Fatal(err)
				}
				if err := f.svc.twoFactor.Disable(t.Context(), api.TwoFactorDisableInput{UserID: f.userID, Password: "OldPass1!", CallerSessionID: f.actor.SessionID}); err != nil {
					t.Fatal(err)
				}
			}
			if f.stored(t).Status != "cancelled" {
				t.Fatal("settings change did not permanently cancel proof")
			}
			if err := f.svc.ConfirmEmailChange(t.Context(), proof); !errors.Is(err, domain.ErrEmailChangeInvalid) {
				t.Fatalf("old proof revived: %v", err)
			}
		})
	}
}

func TestEmailChangeCodesAreDistinctAndActuallyRotate(t *testing.T) {
	f := newEmailFixture(t)
	candidates := []string{"ABCDEFGH", "ABCDEFGH", "JKLMNPQR", "ABCDEFGH", "JKLMNPQR", "STUVWXYZ"}
	f.svc.code = func() (string, error) {
		if len(candidates) == 0 {
			return "", errors.New("unexpected random call")
		}
		code := candidates[0]
		candidates = candidates[1:]
		return code, nil
	}
	r := f.request(t)
	initial := f.proof(t, r)
	if initial.CurrentEmailCode == initial.NewEmailCode {
		t.Fatal("mailbox proofs share a code")
	}
	f.clock = f.clock.Add(time.Minute)
	if _, err := f.svc.ResendEmailChange(t.Context(), api.ResendEmailChangeInput{Actor: f.actor, RequestID: r.RequestID, Destination: "new"}); err != nil {
		t.Fatal(err)
	}
	rotated := f.proof(t, r)
	if rotated.NewEmailCode == initial.NewEmailCode || rotated.NewEmailCode == initial.CurrentEmailCode {
		t.Fatal("resend reused an existing code")
	}
	if err := f.svc.ConfirmEmailChange(t.Context(), initial); !errors.Is(err, domain.ErrEmailChangeInvalid) {
		t.Fatal("old proof survived rotation")
	}
	if err := f.svc.ConfirmEmailChange(t.Context(), rotated); err != nil {
		t.Fatal(err)
	}
}
