package sqlstore

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
)

func TestBackendDeleteUnusedTokenByID(t *testing.T) {
	db := backendDB(t)
	user := backendUser(t, db)
	repo := NewTokenRepository(db)
	now := time.Now().UTC()
	failed, other, used := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, id := range []string{failed, other, used} {
		token := &domain.VerificationToken{
			ID: id, UserID: &user, Email: "user@example.com", TokenHash: id,
			Type: domain.TokenVerifyEmail, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
		if id == used {
			token.UsedAt = &now
		}
		if err := repo.Create(t.Context(), token); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{failed, failed, used} {
		if err := repo.DeleteUnusedByID(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	if token, err := repo.GetByID(t.Context(), failed); err != nil || token != nil {
		t.Fatalf("failed token still present: %+v, %v", token, err)
	}
	for _, id := range []string{other, used} {
		if token, err := repo.GetByID(t.Context(), id); err != nil || token == nil {
			t.Fatalf("unrelated or consumed token removed: %+v, %v", token, err)
		}
	}
}
