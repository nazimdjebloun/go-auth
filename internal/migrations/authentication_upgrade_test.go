package migrations

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestAuthenticationWorkflowUpgradePreservesExistingTokens(t *testing.T) {
	driver := testdb.Selected()
	catalog, err := Load(driver)
	if err != nil {
		t.Fatal(err)
	}
	db := testdb.OpenSelected(t)
	options := Options{Driver: driver}
	prefix := catalogPrefix(t, files, catalog, 2)
	if _, err := runCatalog(t.Context(), db, options, prefix, "apply", 0); err != nil {
		t.Fatal(err)
	}
	store := sqlstore.NewDB(db, driver)
	now := time.Now().UTC().Truncate(time.Second)
	userID := "00000000-0000-4000-8000-000000000001"
	if _, err := store.ExecContext(t.Context(), "INSERT INTO users (id,email,name,role,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6)", userID, "upgrade@example.test", "Upgrade", "user", now, now); err != nil {
		t.Fatal(err)
	}
	types := []domain.TokenType{domain.TokenVerifyEmail, domain.TokenResetPass, domain.TokenSetPass, domain.TokenInviteVerify, domain.TokenOAuthState, domain.TokenDeleteAccount, domain.TokenTwoFactor}
	for i, kind := range types {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+10)
		var used any
		if i%2 == 1 {
			used = now
		}
		if _, err := store.ExecContext(t.Context(), "INSERT INTO verification_tokens (id,user_id,email,token_hash,type,expires_at,used_at,code_verifier,attempts,resend_count,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", id, userID, "upgrade@example.test", "legacy-"+string(kind), kind, now.Add(time.Hour), used, "legacy-pkce", 2, 1, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Apply(t.Context(), db, options); err != nil {
		t.Fatal(err)
	}
	if err := Verify(t.Context(), db, options); err != nil {
		t.Fatal(err)
	}
	tokens := sqlstore.NewTokenRepository(store)
	for i, kind := range types {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i+10)
		token, err := tokens.GetByID(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if token == nil || token.Type != kind || token.TokenHash != "legacy-"+string(kind) || token.UserID == nil || *token.UserID != userID || token.CodeVerifier == nil || *token.CodeVerifier != "legacy-pkce" || token.Attempts != 2 || token.ResendCount != 1 || token.ContextHash != "" || token.EncryptedPayload != "" || !token.ExpiresAt.Equal(now.Add(time.Hour)) || (token.UsedAt != nil) != (i%2 == 1) {
			t.Fatalf("upgrade changed token: %+v", token)
		}
		if claimed, err := tokens.ConsumeIfValidUnderCap(t.Context(), port.ConsumeTokenInput{ID: id, TokenHash: token.TokenHash, UserID: userID, Type: domain.TokenTwoFactorEnable, UsedAt: now}, 5); err != nil || claimed {
			t.Fatalf("legacy token accepted as settings proof: %v %v", claimed, err)
		}
	}
	for _, kind := range []domain.TokenType{domain.TokenTwoFactorEnable, domain.TokenTwoFactorDisable} {
		token := &domain.VerificationToken{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", 100+len(kind)), UserID: &userID, Email: "upgrade@example.test", Type: kind, TokenHash: "new-" + string(kind), ContextHash: strings.Repeat("a", 64), EncryptedPayload: "encrypted", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
		if err := tokens.Create(t.Context(), token); err != nil {
			t.Fatalf("new token type rejected after upgrade: %v", err)
		}
	}
}
