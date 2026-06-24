package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestInviteRegister(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, defaultTestConfig(), sessSvc)

	raw, _ := gen.Generate()
	now := time.Now().UTC()
	invite := &domain.Invite{
		ID:        raw,
		Email:     "invited@example.com",
		Code:      hashToken(raw),
		CreatedBy: "admin-id",
		Status:    domain.InvitePending,
		ExpiresAt: now.Add(defaultTestConfig().InviteTTL),
		CreatedAt: now,
	}
	invites.Create(context.Background(), invite)

	result, err := svc.CompleteInviteRegistration(context.Background(), CompleteInviteInput{
		Code:            raw,
		Name:            "Invited User",
		Password:        "Passw0rd!",
		ConfirmPassword: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("CompleteInviteRegistration failed: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.User.Email != "invited@example.com" {
		t.Fatalf("Expected email invited@example.com, got %s", result.User.Email)
	}
	if !result.User.IsVerified {
		t.Fatal("Expected user to be auto-verified")
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
}

func TestInviteRegisterExpired(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	cfg := defaultTestConfig()
	cfg.InviteTTL = -1 * time.Hour

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, cfg, sessSvc)

	raw, _ := gen.Generate()
	now := time.Now().UTC()
	invite := &domain.Invite{
		ID:        raw,
		Email:     "invited@example.com",
		Code:      hashToken(raw),
		CreatedBy: "admin-id",
		Status:    domain.InvitePending,
		ExpiresAt: now.Add(cfg.InviteTTL),
		CreatedAt: now,
	}
	invites.Create(context.Background(), invite)

	_, err := svc.CompleteInviteRegistration(context.Background(), CompleteInviteInput{
		Code:            raw,
		Name:            "Invited User",
		Password:        "Passw0rd!",
		ConfirmPassword: "Passw0rd!",
	})
	if err == nil {
		t.Fatal("Expected error for expired invite, got nil")
	}
	if err.Code != "invite_expired" {
		t.Fatalf("Expected invite_expired, got %s", err.Code)
	}
}

func TestInviteRegisterPasswordMismatch(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, defaultTestConfig(), sessSvc)

	raw, _ := gen.Generate()
	invite := &domain.Invite{
		ID:        raw,
		Email:     "invited@example.com",
		Code:      hashToken(raw),
		CreatedBy: "admin-id",
		Status:    domain.InvitePending,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	invites.Create(context.Background(), invite)

	_, err := svc.CompleteInviteRegistration(context.Background(), CompleteInviteInput{
		Code:            raw,
		Name:            "Invited User",
		Password:        "Passw0rd!",
		ConfirmPassword: "different",
	})
	if err == nil {
		t.Fatal("Expected error for password mismatch, got nil")
	}
	if err.Code != "passwords_dont_match" {
		t.Fatalf("Expected passwords_dont_match, got %s", err.Code)
	}
}
