package sqlstore

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestBackendRefreshZeroGraceRejectsFutureRotation(t *testing.T) {
	db := backendDB(t)
	user := backendUser(t, db)
	id := uuid.NewString()
	now := time.Now().UTC().Truncate(time.Second)
	future := now.Add(time.Second)
	repo := NewSessionRepository(db)
	if err := repo.Create(t.Context(), &domain.Session{
		ID: id, UserID: user, TokenHash: "access-hash", RefreshTokenHash: "current-hash",
		PreviousRefreshHash: "previous-hash", RefreshRotatedAt: &future,
		ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(time.Hour), CreatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	_, err := repo.UpdateRefreshToken(t.Context(), port.UpdateRefreshInput{
		OldRefreshHash: "previous-hash", NewRefreshHash: "next-hash", NewTokenHash: "next-access",
		RotatedAt: now, NewExpiresAt: now.Add(time.Hour), GraceWindow: 0,
	})
	var replay *port.ErrRefreshTokenReused
	if !errors.As(err, &replay) {
		t.Fatalf("zero-grace replay=%v, want replay revocation", err)
	}
	got, err := repo.GetByTokenHash(t.Context(), "access-hash")
	if err != nil || got != nil {
		t.Fatalf("replayed session survived: %+v %v", got, err)
	}
}
