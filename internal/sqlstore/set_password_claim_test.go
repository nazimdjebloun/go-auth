package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestSetPasswordAndVerifyRequiresExactLiveToken(t *testing.T) {
	for _, name := range []string{"valid", "hash", "user", "type", "expired", "used", "email", "password exists", "missing token"} {
		t.Run(name, func(t *testing.T) {
			db := backendDB(t)
			userID := backendUser(t, db)
			now := time.Now().UTC()
			token := &domain.VerificationToken{ID: "00000000-0000-4000-8000-000000000213", UserID: &userID, Email: userID + "@example.com", TokenHash: "validated-code-hash", Type: domain.TokenSetPass, ExpiresAt: now.Add(time.Hour)}
			input := port.SetPasswordAndVerifyInput{UserID: userID, Email: token.Email, PasswordHash: "new-password-hash", TokenID: token.ID, TokenHash: token.TokenHash}
			switch name {
			case "hash":
				input.TokenHash = "previous-code-hash"
			case "user":
				other := backendUser(t, db)
				token.UserID = &other
			case "type":
				token.Type = domain.TokenResetPass
			case "expired":
				token.ExpiresAt = now.Add(-time.Second)
			case "used":
				token.UsedAt = &now
			case "email":
				input.Email = "old-address@example.com"
			case "password exists":
				if _, err := db.ExecContext(t.Context(), "UPDATE users SET password_hash=$1 WHERE id=$2", "existing-password", userID); err != nil {
					t.Fatal(err)
				}
			}
			tokens := NewTokenRepository(db)
			if name != "missing token" {
				if err := tokens.Create(t.Context(), token); err != nil {
					t.Fatal(err)
				}
			}
			claimed, err := NewUserRepository(db).SetPasswordAndVerify(t.Context(), input)
			if err != nil || claimed != (name == "valid") {
				t.Fatalf("claim=%v, err=%v", claimed, err)
			}
			user, err := NewUserRepository(db).GetByID(t.Context(), userID)
			if err != nil {
				t.Fatal(err)
			}
			if name == "valid" {
				if !user.HasPassword() || !user.IsVerified {
					t.Fatal("valid claim did not install and verify password")
				}
			} else if user.IsVerified || (user.HasPassword() && name != "password exists") {
				t.Fatal("rejected claim changed the user")
			}
			stored, err := tokens.GetByID(t.Context(), token.ID)
			if err != nil {
				t.Fatal(err)
			}
			if name != "valid" && name != "missing token" && (stored.UsedAt != nil) != (name == "used") {
				t.Fatal("rejected claim consumed its token")
			}
		})
	}
}

func TestSetPasswordAndVerifyJoinsOuterTransaction(t *testing.T) {
	db := backendDB(t)
	userID := backendUser(t, db)
	token := &domain.VerificationToken{ID: "00000000-0000-4000-8000-000000000214", UserID: &userID, Email: userID + "@example.com", TokenHash: "set-password-hash", Type: domain.TokenSetPass, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := NewTokenRepository(db).Create(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	want := errors.New("later transaction failure")
	err := db.WithTx(t.Context(), func(ctx context.Context) error {
		ok, err := NewUserRepository(db).SetPasswordAndVerify(ctx, port.SetPasswordAndVerifyInput{UserID: userID, Email: token.Email, PasswordHash: "new-password", TokenID: token.ID, TokenHash: token.TokenHash})
		if err != nil {
			return err
		}
		if !ok {
			t.Fatal("valid claim failed inside outer transaction")
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
	user, err := NewUserRepository(db).GetByID(t.Context(), userID)
	if err != nil || user.HasPassword() || user.IsVerified {
		t.Fatalf("password escaped outer rollback: %+v, %v", user, err)
	}
	stored, err := NewTokenRepository(db).GetByID(t.Context(), token.ID)
	if err != nil || stored.UsedAt != nil {
		t.Fatalf("token escaped outer rollback: %+v, %v", stored, err)
	}
}
