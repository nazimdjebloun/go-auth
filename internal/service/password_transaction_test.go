package service

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/schema"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
	_ "modernc.org/sqlite"
)

var errInjectedSessionRevocation = errors.New("test: injected session revocation failure")

type failingPasswordSessionRevoker struct {
	port.SessionRevoker
}

func (f *failingPasswordSessionRevoker) DeleteAllForUser(context.Context, string) error {
	return errInjectedSessionRevocation
}

func (f *failingPasswordSessionRevoker) DeleteAllForUserExcept(context.Context, string, string) error {
	return errInjectedSessionRevocation
}

type conflictingPasswordUserRepository struct {
	*sqlstore.UserRepository
}

func (r *conflictingPasswordUserRepository) UpdatePasswordHash(
	context.Context,
	string,
	string,
	*uint32,
	string,
	*uint32,
	time.Time,
) (bool, error) {
	return false, nil
}

type resetHashBarrier struct {
	delegate port.Hasher
	calls    atomic.Int32
	release  chan struct{}
	once     sync.Once
}

func newResetHashBarrier(delegate port.Hasher) *resetHashBarrier {
	return &resetHashBarrier{delegate: delegate, release: make(chan struct{})}
}

func (h *resetHashBarrier) Hash(password string) (string, error) {
	if h.calls.Add(1) == 2 {
		h.once.Do(func() { close(h.release) })
	}
	<-h.release
	return h.delegate.Hash(password)
}

func (h *resetHashBarrier) Compare(password, hash string) error {
	return h.delegate.Compare(password, hash)
}

type passwordTransactionFixture struct {
	db       *sqlstore.DB
	users    *sqlstore.UserRepository
	tokens   *sqlstore.TokenRepository
	sessions *sqlstore.SessionRepository
	hasher   *testutil.MockHasher
	userID   string
	oldHash  string
	code     string
	tokenID  string
	session  string
}

func newPasswordTransactionFixture(t *testing.T) *passwordTransactionFixture {
	t.Helper()
	rawDB, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "password.db")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rawDB.Close() })

	ddl, err := schema.For("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range schema.SplitSQL(ddl) {
		if _, err := rawDB.Exec(statement); err != nil {
			t.Fatalf("applying sqlite schema: %v", err)
		}
	}

	db := sqlstore.NewDB(rawDB, "sqlite")
	users := sqlstore.NewUserRepository(db)
	tokens := sqlstore.NewTokenRepository(db)
	sessions := sqlstore.NewSessionRepository(db)
	hasher := &testutil.MockHasher{}
	oldHash, err := hasher.Hash("OldPass1!")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	const userID = "password-transaction-user"
	if err := users.Create(context.Background(), &domain.User{
		ID:           userID,
		Email:        "password-transaction@example.com",
		PasswordHash: &oldHash,
		Name:         "Password Transaction",
		Role:         domain.RoleUser,
		IsVerified:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		t.Fatal(err)
	}

	const code = "atomic-password-reset-code"
	const tokenID = "atomic-password-reset-token"
	if err := tokens.Create(context.Background(), &domain.VerificationToken{
		ID:        tokenID,
		UserID:    stringPointer(userID),
		Email:     "password-transaction@example.com",
		TokenHash: hashToken(code),
		Type:      domain.TokenResetPass,
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	const sessionHash = "atomic-password-reset-session"
	if err := sessions.Create(context.Background(), &domain.Session{
		ID:               "atomic-password-reset-session-id",
		UserID:           userID,
		TokenHash:        sessionHash,
		RefreshTokenHash: "atomic-password-reset-refresh",
		ExpiresAt:        now.Add(time.Hour),
		RefreshExpiresAt: now.Add(2 * time.Hour),
		CreatedAt:        now,
		LastActiveAt:     now,
	}); err != nil {
		t.Fatal(err)
	}

	return &passwordTransactionFixture{
		db:       db,
		users:    users,
		tokens:   tokens,
		sessions: sessions,
		hasher:   hasher,
		userID:   userID,
		oldHash:  oldHash,
		code:     code,
		tokenID:  tokenID,
		session:  sessionHash,
	}
}

func (f *passwordTransactionFixture) passwordService(hasher port.Hasher, sessions port.SessionRevoker) *PasswordService {
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	return NewPasswordService(
		f.users,
		f.tokens,
		hasher,
		&testutil.MockTokenGen{Length: 32},
		nil,
		sessions,
		f.db,
		cfg,
	)
}

func TestResetPassword_TransactionRollsBackPasswordAndTokenWhenSessionRevocationFails(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	svc := f.passwordService(f.hasher, &failingPasswordSessionRevoker{SessionRevoker: f.sessions})

	err := svc.ResetPassword(context.Background(), ResetPasswordInput{Code: f.code, NewPassword: "NewPass1!"})
	if !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("ResetPassword error = %v, want internal_error", err)
	}

	user, err := f.users.GetByID(context.Background(), f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash == nil || *user.PasswordHash != f.oldHash || user.PasswordPepperVersion != nil {
		t.Fatalf("rolled-back reset stored credential = %v/v%v", user.PasswordHash, user.PasswordPepperVersion)
	}
	token, err := f.tokens.GetByID(context.Background(), f.tokenID)
	if err != nil {
		t.Fatal(err)
	}
	if token == nil || token.UsedAt != nil {
		t.Fatal("rolled-back reset consumed its token")
	}
	session, err := f.sessions.GetByTokenHash(context.Background(), f.session)
	if err != nil {
		t.Fatal(err)
	}
	if session == nil {
		t.Fatal("rolled-back reset revoked its session")
	}
}

func TestChangePassword_TransactionRollsBackPasswordWhenSessionRevocationFails(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	svc := f.passwordService(f.hasher, &failingPasswordSessionRevoker{SessionRevoker: f.sessions})

	err := svc.ChangePassword(context.Background(), ChangePasswordInput{
		UserID:      f.userID,
		OldPassword: "OldPass1!",
		NewPassword: "NewPass1!",
	})
	if !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("ChangePassword error = %v, want internal_error", err)
	}

	user, err := f.users.GetByID(context.Background(), f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash == nil || *user.PasswordHash != f.oldHash || user.PasswordPepperVersion != nil {
		t.Fatalf("rolled-back change stored credential = %v/v%v", user.PasswordHash, user.PasswordPepperVersion)
	}
	session, err := f.sessions.GetByTokenHash(context.Background(), f.session)
	if err != nil {
		t.Fatal(err)
	}
	if session == nil {
		t.Fatal("rolled-back change revoked its session")
	}
}

func TestForgotPassword_DummyInsertIsRolledBack(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	mailer := &testutil.MockMailer{}
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	svc := NewPasswordService(
		f.users,
		f.tokens,
		f.hasher,
		&testutil.MockTokenGen{Length: 32},
		mailer,
		f.sessions,
		f.db,
		cfg,
	)

	var before int
	if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM verification_tokens").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := svc.ForgotPassword(context.Background(), ForgotPasswordInput{Email: "missing@example.com"}); err != nil {
		t.Fatalf("ForgotPassword error = %v, want nil", err)
	}
	var after int
	if err := f.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM verification_tokens").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("verification token rows = %d after dummy request, want original %d", after, before)
	}
	if len(mailer.Calls) != 0 {
		t.Fatalf("dummy request sent %d emails, want none", len(mailer.Calls))
	}
}

func TestResetPassword_TransactionRollsBackTokenClaimOnPasswordConflict(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	users := &conflictingPasswordUserRepository{UserRepository: f.users}
	cfg := defaultTestConfig()
	cfg.PasswordPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true, RequireUppercase: true}
	svc := NewPasswordService(
		users,
		f.tokens,
		f.hasher,
		&testutil.MockTokenGen{Length: 32},
		nil,
		f.sessions,
		f.db,
		cfg,
	)

	err := svc.ResetPassword(context.Background(), ResetPasswordInput{Code: f.code, NewPassword: "NewPass1!"})
	if !errors.Is(err, domain.ErrPasswordUpdateConflict) {
		t.Fatalf("ResetPassword error = %v, want password_update_conflict", err)
	}

	token, err := f.tokens.GetByID(context.Background(), f.tokenID)
	if err != nil {
		t.Fatal(err)
	}
	if token == nil || token.UsedAt != nil {
		t.Fatal("password conflict committed the reset token claim")
	}
	session, err := f.sessions.GetByTokenHash(context.Background(), f.session)
	if err != nil {
		t.Fatal(err)
	}
	if session == nil {
		t.Fatal("password conflict revoked sessions")
	}
}

func TestResetPassword_ConcurrentUseCommitsExactlyOnce(t *testing.T) {
	f := newPasswordTransactionFixture(t)
	hasher := newResetHashBarrier(f.hasher)
	svc := f.passwordService(hasher, f.sessions)

	passwords := []string{"WinnerOne1!", "WinnerTwo2!"}
	errs := make(chan error, len(passwords))
	for _, password := range passwords {
		password := password
		go func() {
			errs <- svc.ResetPassword(context.Background(), ResetPasswordInput{Code: f.code, NewPassword: password})
		}()
	}

	successes := 0
	invalid := 0
	for range passwords {
		err := <-errs
		switch {
		case err == nil:
			successes++
		case errors.Is(err, domain.ErrResetTokenInvalid):
			invalid++
		default:
			t.Fatalf("concurrent reset error = %v, want nil or reset_token_invalid", err)
		}
	}
	if successes != 1 || invalid != 1 {
		t.Fatalf("concurrent reset outcomes = %d success/%d invalid, want 1/1", successes, invalid)
	}

	user, err := f.users.GetByID(context.Background(), f.userID)
	if err != nil {
		t.Fatal(err)
	}
	verified := 0
	for _, password := range passwords {
		if f.hasher.Compare(password, *user.PasswordHash) == nil {
			verified++
		}
	}
	if verified != 1 {
		t.Fatalf("stored password verifies %d candidates, want exactly one", verified)
	}
	token, err := f.tokens.GetByID(context.Background(), f.tokenID)
	if err != nil {
		t.Fatal(err)
	}
	if token == nil || token.UsedAt == nil {
		t.Fatal("successful concurrent reset did not consume its token")
	}
	session, err := f.sessions.GetByTokenHash(context.Background(), f.session)
	if err != nil {
		t.Fatal(err)
	}
	if session != nil {
		t.Fatal("successful concurrent reset did not revoke sessions")
	}
}

func stringPointer(value string) *string {
	return &value
}
