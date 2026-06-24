package service

import (
	"context"
	"testing"

	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestValidateSession(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

	registerResult, _ := svc.Register(context.Background(), RegisterInput{
		Email:    "test@example.com",
		Password: "Passw0rd!",
		Name:     "Test",
	})

	user, session, err := svc.ValidateSession(context.Background(), registerResult.SessionToken)
	if err != nil {
		t.Fatalf("ValidateSession failed: %v", err)
	}
	if user == nil {
		t.Fatal("Expected user, got nil")
	}
	if session == nil {
		t.Fatal("Expected session, got nil")
	}
	if user.ID != registerResult.User.ID {
		t.Fatalf("Expected user ID %s, got %s", registerResult.User.ID, user.ID)
	}
}

func TestValidateSessionInvalidToken(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tokens := testutil.NewMockTokenRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewAuthService(users, sessions, tokens, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

	_, _, err := svc.ValidateSession(context.Background(), "invalid-token")
	if err == nil {
		t.Fatal("Expected error for invalid token, got nil")
	}
}
