package service

import (
	"errors"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/hasher/registry"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func newWorkLimitedPasswordHasher(t *testing.T) (*PasswordHasher, *hasher.WorkLimiter) {
	t.Helper()
	l, err := hasher.NewWorkLimiter(1)
	if err != nil {
		t.Fatal(err)
	}
	r, err := registry.NewWithWorkLimiter(argonFakeHasher{}, l, hasher.New(4))
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := NewPasswordHasher(r, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pipeline, l
}

func TestPasswordWorkOverloadHasSameLoginResultForEveryAccount(t *testing.T) {
	pipeline, l := newWorkLimitedPasswordHasher(t)
	users := testutil.NewMockUserRepo()
	stored, err := pipeline.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	user := seedPasswordUser(t, users, "present@example.com", stored)
	unknownPepper := seedPasswordUser(t, users, "pepper@example.com", stored)
	unknownPepper.PasswordPepperVersion = uint32Pointer(2)
	if err := users.Update(t.Context(), unknownPepper); err != nil {
		t.Fatal(err)
	}
	seedPasswordUser(t, users, "corrupt@example.com", "$unknown$hash")
	if err := users.Create(t.Context(), &domain.User{ID: "passwordless", Email: "passwordless@example.com"}); err != nil {
		t.Fatal(err)
	}
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := NewAuthService(&testutil.MockTxManager{}, users, sessions, testutil.NewMockTokenRepo(), pipeline, gen, nil, defaultTestConfig(), newTestSessionService(sessions, gen), nil, nil)
	if err := l.Do(func() error {
		for _, email := range []string{user.Email, "missing@example.com", "passwordless@example.com", "pepper@example.com", "corrupt@example.com"} {
			t.Run(email, func(t *testing.T) {
				if _, err := svc.Login(t.Context(), api.LoginInput{Email: email, Password: "WrongPass1!"}); !errors.Is(err, domain.ErrPasswordWorkBusy) {
					t.Fatalf("Login = %v, want password_work_busy", err)
				}
			})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(t.Context(), api.LoginInput{Email: "missing@example.com", Password: "WrongPass1!"}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("normal dummy verification = %v", err)
	}
}

func TestPasswordWorkOverloadPreservedAcrossCredentialServices(t *testing.T) {
	pipeline, l := newWorkLimitedPasswordHasher(t)
	users := testutil.NewMockUserRepo()
	stored, err := pipeline.Hash("OldPass1!")
	if err != nil {
		t.Fatal(err)
	}
	user := seedPasswordUser(t, users, "work@example.com", stored)
	password := &PasswordService{users: users, hasher: pipeline}
	auth := &AuthService{users: users, hasher: pipeline}
	two := &TwoFactorService{users: users, hasher: pipeline}
	email := &EmailService{users: users, hasher: pipeline}
	if err := l.Do(func() error {
		for _, tc := range []struct {
			name string
			run  func() error
		}{
			{"change password", func() error {
				return password.ChangePassword(t.Context(), api.ChangePasswordInput{UserID: user.ID, OldPassword: "OldPass1!", NewPassword: "NewPass1!"})
			}},
			{"delete account", func() error {
				return auth.DeleteAccount(t.Context(), api.DeleteAccountInput{UserID: user.ID, Password: "OldPass1!"})
			}},
			{"two factor", func() error { _, err := two.authorizeChange(t.Context(), user.ID, "OldPass1!"); return err }},
			{"email change", func() error {
				_, err := email.RequestEmailChange(t.Context(), api.RequestEmailChangeInput{Actor: api.EmailChangeActor{UserID: user.ID, SessionID: "session"}, NewEmail: "new@example.com", Password: "OldPass1!"})
				return err
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if err := tc.run(); !errors.Is(err, domain.ErrPasswordWorkBusy) {
					t.Fatalf("overload = %v", err)
				}
			})
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type rehashBusyHasher struct {
	port.Hasher
	hashCalls int
}

func (h *rehashBusyHasher) Hash(string) (string, error) {
	h.hashCalls++
	return "", domain.ErrPasswordWorkBusy
}
func (*rehashBusyHasher) NeedsRehash(string) bool { return true }
func (*rehashBusyHasher) DummyHash() string       { return "unused$dummy" }

func TestPasswordWorkBusyRehashDoesNotFailVerifiedLogin(t *testing.T) {
	users := testutil.NewMockUserRepo()
	delegate := &testutil.MockHasher{}
	stored, err := delegate.Hash("Passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	user := seedPasswordUser(t, users, "rehash@example.com", stored)
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	busy := &rehashBusyHasher{Hasher: delegate}
	svc := NewAuthService(&testutil.MockTxManager{}, users, sessions, testutil.NewMockTokenRepo(), busy, gen, nil, defaultTestConfig(), newTestSessionService(sessions, gen), nil, nil)
	res, err := svc.Login(t.Context(), api.LoginInput{Email: user.Email, Password: "Passw0rd!"})
	if err != nil || res.Session == nil {
		t.Fatalf("verified login failed on optional rehash: %v", err)
	}
	if busy.hashCalls != 1 {
		t.Fatal("login did not attempt the optional rehash")
	}
	after, err := users.GetByID(t.Context(), user.ID)
	if err != nil || after.PasswordHash == nil || *after.PasswordHash != stored {
		t.Fatal("overloaded rehash changed the credential")
	}
}

func TestPasswordWorkBusySetPasswordPreservesCode(t *testing.T) {
	users := testutil.NewMockUserRepo()
	tokens := testutil.NewMockTokenRepo()
	svc := newTestPasswordService(users, tokens, &testutil.MockHasher{}, &testutil.MockMailer{})
	pipeline, l := newWorkLimitedPasswordHasher(t)
	svc.hasher = pipeline
	const userID = "passwordless-work"
	if err := users.Create(t.Context(), &domain.User{ID: userID, Email: "passwordless-work@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.RequestSetPassword(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	code := testutil.GetLastVerificationCode(svc.mailer.(*testutil.MockMailer))
	input := api.ConfirmSetPasswordInput{UserID: userID, Code: code, NewPassword: "NewPass1!"}
	if err := l.Do(func() error {
		if err := svc.ConfirmSetPassword(t.Context(), input); !errors.Is(err, domain.ErrPasswordWorkBusy) {
			t.Fatalf("ConfirmSetPassword = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	user, err := users.GetByID(t.Context(), userID)
	if err != nil || user.HasPassword() {
		t.Fatal("overloaded password setup installed a credential")
	}
	token, err := tokens.GetLastByUserAndType(t.Context(), userID, domain.TokenSetPass)
	if err != nil || token == nil || token.UsedAt != nil {
		t.Fatal("overloaded password setup consumed its code")
	}
	if err := svc.ConfirmSetPassword(t.Context(), input); err != nil {
		t.Fatalf("retry with preserved setup code: %v", err)
	}
}

func TestPasswordWorkBusyResetPreservesTokenCredentialAndSession(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	pipeline, l := newWorkLimitedPasswordHasher(t)
	svc := f.passwordService(pipeline, f.sessions)
	if err := l.Do(func() error {
		if err := svc.ResetPassword(t.Context(), api.ResetPasswordInput{Code: f.code, NewPassword: "NewPass1!"}); !errors.Is(err, domain.ErrPasswordWorkBusy) {
			t.Fatalf("ResetPassword = %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	user, err := f.users.GetByID(t.Context(), f.userID)
	if err != nil || user.PasswordHash == nil || *user.PasswordHash != f.oldHash || user.PasswordPepperVersion != nil {
		t.Fatal("overloaded reset changed the credential")
	}
	token, err := f.tokens.GetByID(t.Context(), f.tokenID)
	if err != nil || token == nil || token.UsedAt != nil {
		t.Fatal("overloaded reset consumed its token")
	}
	session, err := f.sessions.GetByTokenHash(t.Context(), f.session)
	if err != nil || session == nil {
		t.Fatal("overloaded reset revoked its session")
	}
	if err := svc.ResetPassword(t.Context(), api.ResetPasswordInput{Code: f.code, NewPassword: "NewPass1!"}); err != nil {
		t.Fatalf("retry with preserved reset token: %v", err)
	}
}
