package service

import (
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type setPasswordHashHook struct {
	port.Hasher
	before func()
}

func (h setPasswordHashHook) Hash(password string) (string, error) {
	h.before()
	return h.Hasher.Hash(password)
}

func TestConfirmSetPasswordRechecksTokenAfterHashing(t *testing.T) {
	for _, name := range []string{"expires", "rotates"} {
		t.Run(name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			ctx := t.Context()
			if _, err := f.db.ExecContext(ctx, "UPDATE users SET password_hash=NULL,is_verified=false WHERE id=$1", f.userID); err != nil {
				t.Fatal(err)
			}
			cfg := defaultTestConfig()
			code := "ABCDEFGH"
			if _, err := f.db.ExecContext(ctx, "UPDATE verification_tokens SET type=$1,token_hash=$2 WHERE id=$3", domain.TokenSetPass, hashOTP(code, cfg.OTPPepper), f.tokenID); err != nil {
				t.Fatal(err)
			}
			// Change only after the service compared the live code. Backdating
			// expiry here deterministically models crossing its deadline during
			// expensive hashing, without sleep-based timing assertions.
			hasher := setPasswordHashHook{Hasher: f.hasher, before: func() {
				query, value := "UPDATE verification_tokens SET expires_at=$1 WHERE id=$2", any(time.Now().UTC().Add(-time.Second))
				if name == "rotates" {
					query, value = "UPDATE verification_tokens SET token_hash=$1 WHERE id=$2", hashOTP("NEWHASH2", cfg.OTPPepper)
				}
				if _, err := f.db.ExecContext(ctx, query, value, f.tokenID); err != nil {
					t.Fatal(err)
				}
			}}
			if err := f.passwordService(hasher, f.sessions).ConfirmSetPassword(ctx, api.ConfirmSetPasswordInput{UserID: f.userID, Code: code, NewPassword: "NewPass2!"}); !errors.Is(err, domain.ErrSetPasswordCodeUsed) {
				t.Fatalf("stale proof accepted after KDF: %v", err)
			}
			user, err := f.users.GetByID(ctx, f.userID)
			if err != nil || user.HasPassword() || user.IsVerified {
				t.Fatalf("stale proof changed user: %+v, %v", user, err)
			}
			token, err := f.tokens.GetByID(ctx, f.tokenID)
			if err != nil || token.UsedAt != nil {
				t.Fatalf("stale proof consumed token: %+v, %v", token, err)
			}
		})
	}
}
