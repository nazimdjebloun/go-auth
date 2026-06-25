package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ─── POST /auth/verify-email ───────────────────────────────────────

func TestVerifyEmail_HappyPath(t *testing.T) {
	th := newTestHarness()

	uid := "user-1"
	user := &domain.User{
		ID:         uid,
		Email:      "test@example.com",
		Name:       "Test",
		Role:       domain.RoleUser,
		IsVerified: false,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	th.users.Create(nil, user)

	code := "ABC123"
	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        "tok-1",
		UserID:    &uid,
		Email:     "test@example.com",
		TokenHash: hashToken(code),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(15 * time.Minute),
	}
	th.tokens.Create(nil, token)

	body := `{"code":"ABC123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/verify-email", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.VerifyEmail(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	updated, _ := th.users.GetByID(nil, uid)
	if !updated.IsVerified {
		t.Fatal("expected user to be verified")
	}
}

func TestVerifyEmail_MissingCode(t *testing.T) {
	th := newTestHarness()

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/auth/verify-email", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.VerifyEmail(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.StatusCode)
	}
}

func TestVerifyEmail_ExpiredCode(t *testing.T) {
	th := newTestHarness()

	uid := "user-2"
	user := &domain.User{
		ID:         uid,
		Email:      "test2@example.com",
		Name:       "Test",
		Role:       domain.RoleUser,
		IsVerified: false,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	th.users.Create(nil, user)

	code := "EXPIRED"
	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        "tok-expired",
		UserID:    &uid,
		Email:     "test2@example.com",
		TokenHash: hashToken(code),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(-1 * time.Hour),
	}
	th.tokens.Create(nil, token)

	body := `{"code":"EXPIRED"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/verify-email", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.VerifyEmail(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusGone {
		t.Fatalf("expected 410, got %d", res.StatusCode)
	}
}

// ─── POST /auth/resend-verification ─────────────────────────────────

func TestResendVerification_HappyPath(t *testing.T) {
	th := newTestHarness()

	user := &domain.User{
		ID:         "user-resend",
		Email:      "resend@example.com",
		Name:       "Resend",
		Role:       domain.RoleUser,
		IsVerified: false,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	th.users.Create(nil, user)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/auth/resend-verification", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), user))
	w := httptest.NewRecorder()
	th.handler.ResendVerification(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	if len(th.mailer.Calls) != 1 {
		t.Fatalf("expected 1 mailer call, got %d", len(th.mailer.Calls))
	}
	if th.mailer.Calls[0].To != "resend@example.com" {
		t.Fatalf("expected mail to resend@example.com, got %s", th.mailer.Calls[0].To)
	}
}

func TestResendVerification_Unauthenticated(t *testing.T) {
	th := newTestHarness()

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/auth/resend-verification", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.ResendVerification(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", res.StatusCode)
	}
}
