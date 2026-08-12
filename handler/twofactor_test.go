package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// seedTwoFactorUser creates a verified user with a known password hash
// (matching mockHasher's scheme) and, unless enabled is false, turns on
// per-user 2FA via the same service path Enable2FA uses.
func seedTwoFactorUser(t *testing.T, th *testHarness, id, email, password string, enabled bool) *domain.User {
	t.Helper()
	sum := sha256.Sum256([]byte(password))
	hash := hex.EncodeToString(sum[:])
	user := &domain.User{
		ID:           id,
		Email:        email,
		PasswordHash: &hash,
		Name:         "Test User",
		Role:         domain.RoleUser,
		IsVerified:   true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := th.users.Create(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	if enabled {
		if aerr := th.twoFactor.Enable(context.Background(), user.ID, password, true, ""); aerr != nil {
			t.Fatal(aerr)
		}
	}
	return user
}

func extractCode(t *testing.T, body string) string {
	t.Helper()
	i := strings.Index(body, "Your code: ")
	if i < 0 {
		t.Fatalf("could not find code in email body: %q", body)
	}
	rest := body[i+len("Your code: "):]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[:nl]
	}
	return strings.TrimSpace(rest)
}

func TestLogin_RequiresTwoFactor_GatedResponseNoSessionCookie(t *testing.T) {
	th := newTestHarness()
	seedTwoFactorUser(t, th, "user-2fa-1", "dana@example.com", "Passw0rd!", true)

	body := `{"email":"dana@example.com","password":"Passw0rd!"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Login(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	for _, c := range res.Cookies() {
		if c.Name == "goauth_session" || c.Name == "goauth_refresh" {
			t.Errorf("gated login must not set %s cookie", c.Name)
		}
	}

	var bindingCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "_2fa_challenge" {
			bindingCookie = c
		}
	}
	if bindingCookie == nil {
		t.Fatal("expected the challenge binding cookie to be set")
	}
	if !bindingCookie.HttpOnly {
		t.Error("expected binding cookie to be HttpOnly")
	}

	var resp map[string]any
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["requiresTwoFactor"] != true {
		t.Errorf("expected requiresTwoFactor: true, got %v", resp["requiresTwoFactor"])
	}
	if resp["challengeId"] == nil || resp["challengeId"] == "" {
		t.Error("expected a non-empty challengeId")
	}
}

func TestVerifyTwoFactor_HappyPath_SetsSessionAndClearsBindingCookie(t *testing.T) {
	th := newTestHarness()
	seedTwoFactorUser(t, th, "user-2fa-2", "erin@example.com", "Passw0rd!", true)

	loginBody := `{"email":"erin@example.com","password":"Passw0rd!"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	th.handler.Login(loginW, loginReq)

	loginRes := loginW.Result()
	var loginResp map[string]any
	if err := json.NewDecoder(loginRes.Body).Decode(&loginResp); err != nil {
		t.Fatal(err)
	}
	challengeID, _ := loginResp["challengeId"].(string)
	if challengeID == "" {
		t.Fatal("expected a challengeId from login")
	}
	var bindingCookie *http.Cookie
	for _, c := range loginRes.Cookies() {
		if c.Name == "_2fa_challenge" {
			bindingCookie = c
		}
	}
	if bindingCookie == nil {
		t.Fatal("expected a binding cookie from login")
	}

	code := extractCode(t, th.mailer.Calls[len(th.mailer.Calls)-1].Text)

	verifyBody := `{"challengeId":"` + challengeID + `","code":"` + code + `"}`
	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", strings.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.AddCookie(bindingCookie)
	verifyW := httptest.NewRecorder()
	th.handler.VerifyTwoFactor(verifyW, verifyReq)

	verifyRes := verifyW.Result()
	if verifyRes.StatusCode != http.StatusOK {
		body, _ := json.Marshal(verifyRes.Header)
		t.Fatalf("expected 200, got %d (headers: %s)", verifyRes.StatusCode, body)
	}

	var sessionCookie, clearedBinding *http.Cookie
	for _, c := range verifyRes.Cookies() {
		switch c.Name {
		case "goauth_session":
			sessionCookie = c
		case "_2fa_challenge":
			clearedBinding = c
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatal("expected a session cookie after successful 2fa verify")
	}
	if clearedBinding == nil || clearedBinding.MaxAge != -1 {
		t.Error("expected the binding cookie to be cleared after verify")
	}
}

func TestVerifyTwoFactor_MissingBindingCookie_Rejected(t *testing.T) {
	th := newTestHarness()
	seedTwoFactorUser(t, th, "user-2fa-3", "frank@example.com", "Passw0rd!", true)

	loginBody := `{"email":"frank@example.com","password":"Passw0rd!"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	th.handler.Login(loginW, loginReq)

	var loginResp map[string]any
	if err := json.NewDecoder(loginW.Result().Body).Decode(&loginResp); err != nil {
		t.Fatal(err)
	}
	challengeID, _ := loginResp["challengeId"].(string)
	code := extractCode(t, th.mailer.Calls[len(th.mailer.Calls)-1].Text)

	// No binding cookie attached.
	verifyBody := `{"challengeId":"` + challengeID + `","code":"` + code + `"}`
	verifyReq := httptest.NewRequest(http.MethodPost, "/auth/2fa/verify", strings.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyW := httptest.NewRecorder()
	th.handler.VerifyTwoFactor(verifyW, verifyReq)

	if verifyW.Result().StatusCode == http.StatusOK {
		t.Fatal("expected verify to fail without the binding cookie")
	}
	for _, c := range verifyW.Result().Cookies() {
		if c.Name == "goauth_session" {
			t.Error("must not issue a session when the binding cookie is missing")
		}
	}
}

func TestResendTwoFactor_HappyPath(t *testing.T) {
	th := newTestHarness()
	seedTwoFactorUser(t, th, "user-2fa-4", "gina@example.com", "Passw0rd!", true)

	loginBody := `{"email":"gina@example.com","password":"Passw0rd!"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	th.handler.Login(loginW, loginReq)

	loginRes := loginW.Result()
	var loginResp map[string]any
	if err := json.NewDecoder(loginRes.Body).Decode(&loginResp); err != nil {
		t.Fatal(err)
	}
	challengeID, _ := loginResp["challengeId"].(string)
	var bindingCookie *http.Cookie
	for _, c := range loginRes.Cookies() {
		if c.Name == "_2fa_challenge" {
			bindingCookie = c
		}
	}

	resendBody := `{"challengeId":"` + challengeID + `"}`
	resendReq := httptest.NewRequest(http.MethodPost, "/auth/2fa/resend", strings.NewReader(resendBody))
	resendReq.Header.Set("Content-Type", "application/json")
	resendReq.AddCookie(bindingCookie)
	resendW := httptest.NewRecorder()
	th.handler.ResendTwoFactor(resendW, resendReq)

	res := resendW.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var resp map[string]any
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["challengeId"] != challengeID {
		t.Errorf("expected resend to keep the same challengeId, got %v", resp["challengeId"])
	}
	if resp["codeSent"] != true {
		t.Errorf("expected codeSent: true, got %v", resp["codeSent"])
	}
}

func TestEnable2FA_RequiresAuth(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/enable", strings.NewReader(`{"password":"Passw0rd!"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Enable2FA(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no authenticated user in context, got %d", w.Result().StatusCode)
	}
}

func TestEnable2FA_HappyPath_PersistsFlag(t *testing.T) {
	th := newTestHarness()
	user := seedTwoFactorUser(t, th, "user-2fa-5", "holly@example.com", "Passw0rd!", false)

	body := `{"password":"Passw0rd!"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/enable", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), user))
	w := httptest.NewRecorder()
	th.handler.Enable2FA(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	stored, err := th.users.GetByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.TwoFactorEnabled {
		t.Error("expected two-factor to be enabled after Enable2FA")
	}
}

func TestDisable2FA_HappyPath_PersistsFlag(t *testing.T) {
	th := newTestHarness()
	user := seedTwoFactorUser(t, th, "user-2fa-6", "ivan@example.com", "Passw0rd!", true)

	body := `{"password":"Passw0rd!"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/disable", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), user))
	w := httptest.NewRecorder()
	th.handler.Disable2FA(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	stored, err := th.users.GetByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.TwoFactorEnabled {
		t.Error("expected two-factor to be disabled after Disable2FA")
	}
}

func TestDisable2FA_WrongPassword_Rejected(t *testing.T) {
	th := newTestHarness()
	user := seedTwoFactorUser(t, th, "user-2fa-7", "jack@example.com", "Passw0rd!", true)

	body := `{"password":"WrongPassword!"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/2fa/disable", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), user))
	w := httptest.NewRecorder()
	th.handler.Disable2FA(w, req)

	if w.Result().StatusCode == http.StatusOK {
		t.Fatal("expected disable to fail with the wrong password")
	}
	stored, err := th.users.GetByID(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !stored.TwoFactorEnabled {
		t.Error("two-factor must stay enabled when the password check fails")
	}
}
