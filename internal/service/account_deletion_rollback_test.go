package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/port"
)

var errDeletionCodeWrite = errors.New("test: deletion-code write failed")

type failingDeletionCodeStore struct{ port.TokenRepository }

func (s *failingDeletionCodeStore) MarkUsed(context.Context, string) error {
	return errDeletionCodeWrite
}

func (s *failingDeletionCodeStore) ConsumeIfValid(ctx context.Context, input port.ConsumeTokenInput) (bool, error) {
	// Fail after the real write to prove the claim itself is rolled back.
	if _, err := s.TokenRepository.ConsumeIfValid(ctx, input); err != nil {
		return false, err
	}
	return false, errDeletionCodeWrite
}

func TestConfirmDeleteAccount_CodeWriteFailurePreservesAccount(t *testing.T) {
	// This fixture uses the real SQLite schema, foreign keys, and repositories.
	f := newPasswordTransactionFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := defaultTestConfig()
	cfg.OTPPepper = []byte("deletion-rollback-test-pepper-32bytes")
	const code = "ABCDEFGH"
	if _, err := f.db.ExecContext(ctx, "UPDATE users SET password_hash = NULL WHERE id = $1", f.userID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(ctx, "UPDATE verification_tokens SET type = $1, token_hash = $2 WHERE id = $3", domain.TokenDeleteAccount, hashOTP(code, cfg.OTPPepper), f.tokenID); err != nil {
		t.Fatal(err)
	}
	tokens := &failingDeletionCodeStore{TokenRepository: f.tokens}
	svc := NewAuthService(f.users, f.sessions, tokens, f.hasher, nil, nil, cfg, nil, nil, nil)
	svc.AttachAccountDeletion(NewAccountDeletion(f.db, sqlstore.NewOrgRepository(f.db), f.sessions, f.users))

	err := svc.ConfirmDeleteAccount(ctx, api.ConfirmDeleteAccountInput{UserID: f.userID, Code: code})
	if err == nil {
		t.Fatal("expected deletion-code write failure")
	}
	user, err := f.users.GetByID(ctx, f.userID)
	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("code write failed but account deletion committed")
	}
	session, err := f.sessions.GetByTokenHash(ctx, f.session)
	if err != nil {
		t.Fatal(err)
	}
	if session == nil {
		t.Fatal("code write failed but session revocation committed")
	}
	token, err := f.tokens.GetByID(ctx, f.tokenID)
	if err != nil {
		t.Fatal(err)
	}
	if token == nil || token.UsedAt != nil {
		t.Fatal("failed deletion removed or consumed its retryable code")
	}
}
