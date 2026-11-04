package migrations

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestEmailChangeUpgradePreservesIdentityAndCredentials(t *testing.T) {
	driver := testdb.Selected()
	catalog, err := Load(driver)
	if err != nil {
		t.Fatal(err)
	}
	db := testdb.OpenSelected(t)
	options := Options{Driver: driver}
	prefix := catalogPrefix(t, files, catalog, 3)
	if _, err := runCatalog(t.Context(), db, options, prefix, "apply", 0); err != nil {
		t.Fatal(err)
	}
	store := sqlstore.NewDB(db, driver)
	users := sqlstore.NewUserRepository(store)
	tokens := sqlstore.NewTokenRepository(store)
	sessions := sqlstore.NewSessionRepository(store)
	const userID = "00000000-0000-4000-8000-000000000090"
	now := time.Now().UTC().Truncate(time.Second)
	hash := "existing-password-verifier"
	if err := users.Create(t.Context(), &domain.User{ID: userID, Email: "preserved@example.com", Name: "Preserved", Role: domain.RoleUser, PasswordHash: &hash, IsVerified: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	token := &domain.VerificationToken{ID: "00000000-0000-4000-8000-000000000091", UserID: func() *string { v := userID; return &v }(), Email: "preserved@example.com", TokenHash: "existing-token-hash", Type: domain.TokenResetPass, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := tokens.Create(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Create(t.Context(), &domain.Session{ID: "00000000-0000-4000-8000-000000000092", UserID: userID, TokenHash: "existing-session-hash", RefreshTokenHash: "existing-refresh-hash", CreatedAt: now, LastActiveAt: now, ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(t.Context(), db, options); err != nil {
		t.Fatal(err)
	}
	if err := Verify(t.Context(), db, options); err != nil {
		t.Fatal(err)
	}
	u, err := users.GetByID(t.Context(), userID)
	if err != nil || u.Email != "preserved@example.com" || u.PasswordHash == nil || *u.PasswordHash != hash || !u.IsVerified || u.Name != "Preserved" {
		t.Fatalf("changed user: %+v %v", u, err)
	}
	if v, err := tokens.GetByID(t.Context(), token.ID); err != nil || v == nil || v.TokenHash != token.TokenHash {
		t.Fatal("upgrade changed reset credential")
	}
	if v, err := sessions.GetByTokenHash(t.Context(), "existing-session-hash"); err != nil || v == nil || v.RefreshTokenHash != "existing-refresh-hash" {
		t.Fatal("upgrade changed session")
	}
	repo := sqlstore.NewEmailChangeRepository(store)
	if err := store.WithTx(t.Context(), func(ctx context.Context) error {
		if _, err := users.GetByIDForUpdate(ctx, userID); err != nil {
			return err
		}
		if v, err := repo.Load(ctx, userID); err != nil || v != nil {
			t.Fatalf("new account slot: %v %v", v, err)
		}
		return repo.Save(ctx, &port.EmailChangeRequest{UserID: userID, ID: "request", SessionID: "session", Scope: "app", CurrentEmail: u.Email, NewEmail: "new@example.com", Status: "pending", CurrentCodeHash: "hash-a", NewCodeHash: "hash-b", IdentityHash: "identity", CreatedAt: now, ExpiresAt: now.Add(time.Minute), BudgetStartedAt: now, CurrentSentAt: now, NewSentAt: now, Starts: 1})
	}); err != nil {
		t.Fatal(err)
	}
	if err := users.Delete(t.Context(), userID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM email_change_requests WHERE user_id=$1", userID).Scan(&count); err != nil || count != 0 {
		t.Fatal("account deletion did not cascade email state")
	}
	if _, err := Apply(t.Context(), db, options); err != nil {
		t.Fatal(err)
	}
}
