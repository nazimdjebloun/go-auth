package sqlstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
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

func TestPostgres_SetPasswordExpiryAfterTokenLockWait(t *testing.T) {
	if testdb.Selected() != "postgres" {
		t.Skip("requires selected PostgreSQL backend")
	}
	testSetPasswordExpiryAfterTokenLockWait(t)
}

func TestMySQL_SetPasswordExpiryAfterTokenLockWait(t *testing.T) {
	if testdb.Selected() != "mysql" {
		t.Skip("requires selected MySQL backend")
	}
	testSetPasswordExpiryAfterTokenLockWait(t)
}

func testSetPasswordExpiryAfterTokenLockWait(t *testing.T) {
	t.Helper()
	db := backendDB(t)
	userID := backendUser(t, db)
	token := &domain.VerificationToken{ID: "00000000-0000-4000-8000-000000000215", UserID: &userID, Email: userID + "@example.com", TokenHash: "validated-hash", Type: domain.TokenSetPass, ExpiresAt: time.Now().UTC().Add(time.Hour)}
	if err := NewTokenRepository(db).Create(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	holder, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Rollback() }()
	var tokenID string
	if err := holder.QueryRowContext(ctx, db.Rebind("SELECT id FROM verification_tokens WHERE id=$1 FOR UPDATE"), token.ID).Scan(&tokenID); err != nil {
		t.Fatal(err)
	}
	connectionQuery := "SELECT pg_backend_pid()"
	waitQuery := "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))"
	if db.Driver() == "mysql" {
		connectionQuery = "SELECT CONNECTION_ID()"
		waitQuery = "SELECT EXISTS(SELECT 1 FROM performance_schema.data_lock_waits w JOIN performance_schema.threads t ON t.THREAD_ID=w.BLOCKING_THREAD_ID WHERE t.PROCESSLIST_ID=$1)"
	}
	var connectionID int64
	if err := holder.QueryRowContext(ctx, connectionQuery).Scan(&connectionID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		claimed bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		claimed, err := NewUserRepository(db).SetPasswordAndVerify(ctx, port.SetPasswordAndVerifyInput{UserID: userID, Email: token.Email, PasswordHash: "new-password", TokenID: token.ID, TokenHash: token.TokenHash})
		done <- result{claimed, err}
	}()
	// Observe the actual database wait before changing expiry, so the claim
	// must already have reached the token with any pre-lock time sample.
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := db.QueryRowContext(ctx, waitQuery, connectionID).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case got := <-done:
			t.Fatalf("claim returned before token lock was released: %+v", got)
		case <-ctx.Done():
			t.Fatal("claim never waited on the held token lock")
		case <-ticker.C:
		}
	}
	expiredAt := time.Now().UTC()
	if db.Driver() == "mysql" {
		// MySQL stores these timestamps at second precision. Cross a second
		// boundary so the new expiry is later than a pre-lock time sample.
		expiredAt = expiredAt.Truncate(time.Second).Add(time.Second)
		timer := time.NewTimer(time.Until(expiredAt))
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal("deadline while advancing past MySQL timestamp precision")
		}
	}
	if _, err := holder.ExecContext(ctx, db.Rebind("UPDATE verification_tokens SET expires_at=$1 WHERE id=$2"), expiredAt, token.ID); err != nil {
		t.Fatal(err)
	}
	if err := holder.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.claimed {
			t.Fatalf("expired token claim: %+v", got)
		}
	case <-ctx.Done():
		t.Fatal("claim did not finish after token lock release")
	}
	user, err := NewUserRepository(db).GetByID(ctx, userID)
	if err != nil || user.HasPassword() || user.IsVerified {
		t.Fatalf("expired token changed user: %+v, %v", user, err)
	}
	stored, err := NewTokenRepository(db).GetByID(ctx, token.ID)
	if err != nil || stored.UsedAt != nil {
		t.Fatalf("expired token was consumed: %+v, %v", stored, err)
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
