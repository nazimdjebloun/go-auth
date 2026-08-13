package service

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestCreateSession_ReturnsRefreshToken(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := newTestSessionService(sessions, gen)

	result, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if result.RefreshToken == "" {
		t.Fatal("expected non-empty refresh token")
	}
}

func TestRefreshSession_HappyPath(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := newTestSessionService(sessions, gen)

	createResult, err := svc.Create(context.Background(), "user-1", "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}

	refreshResult, err := svc.RefreshSession(context.Background(), createResult.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if refreshResult.Session == nil {
		t.Fatal("expected session, got nil")
	}
	if refreshResult.Session.UserID != "user-1" {
		t.Fatalf("expected user-1, got %s", refreshResult.Session.UserID)
	}
	if refreshResult.SessionToken == "" {
		t.Fatal("expected new session token")
	}
	if refreshResult.RefreshToken == "" {
		t.Fatal("expected new refresh token")
	}
}

func TestRefreshSession_InvalidToken(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := newTestSessionService(sessions, gen)

	_, err := svc.RefreshSession(context.Background(), "garbage-token")
	if err != domain.ErrInvalidRefreshToken {
		t.Fatalf("expected ErrInvalidRefreshToken, got %v", err)
	}
}

func TestRefreshSession_ExpiredSession(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := NewSessionService(sessions, gen, SessionConfig{
		CookieName:        "goauth_session",
		RefreshCookieName: "goauth_refresh",
		Duration:          -1 * time.Hour,
		IdleTTL:           7 * 24 * time.Hour,
		RefreshTTL:        -1 * time.Hour,
		Path:              "/",
		Secure:            false,
		SameSite:          http.SameSiteLaxMode,
	})

	createResult, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.RefreshSession(context.Background(), createResult.RefreshToken)
	if err != domain.ErrRefreshExpired {
		t.Fatalf("expected ErrRefreshExpired, got %v", err)
	}
}

func TestRefreshSession_ExpiredRefreshToken(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := NewSessionService(sessions, gen, SessionConfig{
		CookieName:        "goauth_session",
		RefreshCookieName: "goauth_refresh",
		Duration:          30 * 24 * time.Hour,
		IdleTTL:           7 * 24 * time.Hour,
		RefreshTTL:        -1 * time.Hour,
		Path:              "/",
		Secure:            false,
		SameSite:          http.SameSiteLaxMode,
	})

	createResult, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.RefreshSession(context.Background(), createResult.RefreshToken)
	if err != domain.ErrRefreshExpired {
		t.Fatalf("expected ErrRefreshExpired, got %v", err)
	}
}

func TestRefreshSession_ReuseDetection(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := newTestSessionServiceNoGrace(sessions, gen)

	createResult, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	refreshToken := createResult.RefreshToken

	// First refresh succeeds
	firstRefresh, err := svc.RefreshSession(context.Background(), refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	newRefreshToken := firstRefresh.RefreshToken

	// Second refresh with old token triggers reuse detection
	_, err = svc.RefreshSession(context.Background(), refreshToken)
	if err != domain.ErrSessionRevoked {
		t.Fatalf("expected ErrSessionRevoked for reuse, got %v", err)
	}

	// Session was revoked (deleted) — new token also fails
	_, err = svc.RefreshSession(context.Background(), newRefreshToken)
	if err == nil {
		t.Fatal("expected error after session revoked")
	}
}

func TestRefreshSession_RotatesTokens(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := newTestSessionServiceNoGrace(sessions, gen)

	createResult, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	refreshToken := createResult.RefreshToken

	// First refresh with current token succeeds
	firstRefresh, err := svc.RefreshSession(context.Background(), refreshToken)
	if err != nil {
		t.Fatal(err)
	}
	newRefreshToken := firstRefresh.RefreshToken

	// Old token is now a previous hash — triggers reuse detection
	_, err = svc.RefreshSession(context.Background(), refreshToken)
	if err != domain.ErrSessionRevoked {
		t.Fatalf("expected reuse detection for old token, got %v", err)
	}

	// New token no longer works (session was revoked by reuse detection)
	_, err = svc.RefreshSession(context.Background(), newRefreshToken)
	if err == nil {
		t.Fatal("expected error after session revoked")
	}
}

func TestRefreshSession_UpdatedSessionFields(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := newTestSessionService(sessions, gen)

	createResult, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	origSession := createResult.Session
	origSessionToken := createResult.SessionToken

	origTokenHash := origSession.TokenHash

	refreshResult, err := svc.RefreshSession(context.Background(), createResult.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	newSession := refreshResult.Session
	newSessionToken := refreshResult.SessionToken

	if newSession.ID != origSession.ID {
		t.Fatal("session ID should stay the same")
	}
	if newSession.TokenHash == origTokenHash {
		t.Fatal("token hash should change after refresh")
	}
	if newSession.PreviousRefreshHash == "" {
		t.Fatal("previous refresh hash should be set after refresh")
	}
	if newSession.RefreshRotatedAt == nil {
		t.Fatal("refresh rotated at should be set after refresh")
	}

	// Old session token should no longer work
	_, err = sessions.GetByTokenHash(context.Background(), hashToken(origSessionToken))
	if err != nil {
		t.Fatal(err)
	}

	// New session token should be findable
	stored, err := sessions.GetByTokenHash(context.Background(), hashToken(newSessionToken))
	if err != nil || stored == nil {
		t.Fatal("new session token should be findable in the repo")
	}
}

func TestRefreshSession_DeletedSession(t *testing.T) {
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := newTestSessionService(sessions, gen)

	createResult, err := svc.Create(context.Background(), "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.RevokeByID(context.Background(), createResult.Session.ID); err != nil {
		t.Fatal(err)
	}

	_, err = svc.RefreshSession(context.Background(), createResult.RefreshToken)
	if err == nil {
		t.Fatal("expected error after session deleted")
	}
}

func TestRefreshSession_ConcurrentRace(t *testing.T) {
	ctx := context.Background()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := newTestSessionService(sessions, gen)

	createResult, err := svc.Create(ctx, "user-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	refreshToken := createResult.RefreshToken

	var (
		wg   sync.WaitGroup
		ok   int32
		errs int32
	)

	n := 10
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.RefreshSession(ctx, refreshToken)
			if err == nil {
				atomic.AddInt32(&ok, 1)
			} else {
				atomic.AddInt32(&errs, 1)
			}
		}()
	}
	wg.Wait()

	if ok == 0 {
		t.Fatal("expected at least one refresh to succeed")
	}
	if ok > 1 {
		t.Fatalf("expected exactly one refresh to succeed, got %d", ok)
	}
	if int(errs) != n-1 {
		t.Fatalf("expected %d refreshes to fail, got %d", n-1, errs)
	}
}
