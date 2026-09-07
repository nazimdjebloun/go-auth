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

func createAdminUser(t *testing.T, th *testHarness, email, password string) {
	t.Helper()
	sum := sha256.Sum256([]byte(password))
	hash := hex.EncodeToString(sum[:])
	user := &domain.User{
		ID:           "admin-" + email,
		Email:        email,
		PasswordHash: &hash,
		Name:         "Admin",
		Role:         domain.RoleAdmin,
		IsVerified:   true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := th.users.Create(context.Background(), user); err != nil {
		t.Fatalf("failed to create admin user: %v", err)
	}
}

func TestRegisterSetsCookieAndHidesToken(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"alice@example.com","password":"Passw0rd!","name":"Alice"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Register(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", res.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "goauth_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected goauth_session cookie to be set")
	}
	if !sessionCookie.HttpOnly {
		t.Error("expected cookie to be HttpOnly")
	}
	if sessionCookie.Value == "" {
		t.Error("expected non-empty cookie value")
	}

	var resp map[string]any
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["sessionToken"]; ok {
		t.Error("sessionToken must not appear in JSON response body")
	}
}

func TestLoginSetsCookieAndHidesToken(t *testing.T) {
	th := newTestHarness()

	regBody := `{"email":"bob@example.com","password":"Passw0rd!","name":"Bob"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Register(w, req)

	user, _ := th.users.GetByEmail(context.Background(), "bob@example.com")
	if user != nil {
		user.IsVerified = true
	}

	loginBody := `{"email":"bob@example.com","password":"Passw0rd!"}`
	req2 := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(loginBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	th.handler.Login(w2, req2)

	res := w2.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "goauth_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected goauth_session cookie after login")
	}
	if sessionCookie.Value == "" {
		t.Error("expected non-empty cookie value")
	}

	var resp map[string]any
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["sessionToken"]; ok {
		t.Error("sessionToken must not appear in JSON response body")
	}
}

func TestLogoutInvalidatesToken(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"carol@example.com","password":"Passw0rd!","name":"Carol"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Register(w, req)

	resp := w.Result()
	var token, refreshToken string
	for _, c := range resp.Cookies() {
		switch c.Name {
		case "goauth_session":
			token = c.Value
		case "goauth_refresh":
			refreshToken = c.Value
		}
	}
	if token == "" {
		t.Fatal("no session cookie received")
	}
	if refreshToken == "" {
		t.Fatal("no refresh cookie received")
	}

	req2 := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "goauth_session", Value: token})
	w2 := httptest.NewRecorder()
	th.handler.Logout(w2, req2)

	res := w2.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	// Session should be invalid after logout
	_, err := th.handler.services.Session.Validate(context.Background(), token)
	if err == nil {
		t.Fatal("expected session to be invalid after logout")
	}

	// Refresh cookie should be cleared
	var refreshCleared bool
	for _, c := range res.Cookies() {
		if c.Name == "goauth_refresh" && c.MaxAge == -1 {
			refreshCleared = true
		}
	}
	if !refreshCleared {
		t.Error("expected refresh cookie to be cleared on logout")
	}
}

func TestRefresh_SetsNewCookies(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"dave@example.com","password":"Passw0rd!","name":"Dave"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Register(w, req)

	var refreshToken string
	for _, c := range w.Result().Cookies() {
		if c.Name == "goauth_refresh" {
			refreshToken = c.Value
			break
		}
	}
	if refreshToken == "" {
		t.Fatal("no refresh cookie received")
	}

	req2 := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req2.AddCookie(&http.Cookie{Name: "goauth_refresh", Value: refreshToken})
	w2 := httptest.NewRecorder()
	th.handler.RefreshToken(w2, req2)

	res := w2.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var newSessionCookie, newRefreshCookie *http.Cookie
	for _, c := range res.Cookies() {
		switch c.Name {
		case "goauth_session":
			newSessionCookie = c
		case "goauth_refresh":
			newRefreshCookie = c
		}
	}
	if newSessionCookie == nil || newSessionCookie.Value == "" {
		t.Fatal("expected new session cookie")
	}
	if newRefreshCookie == nil || newRefreshCookie.Value == "" {
		t.Fatal("expected new refresh cookie")
	}
	if newRefreshCookie.Path != "/" {
		t.Errorf("expected refresh cookie path /, got %q", newRefreshCookie.Path)
	}
	if !newRefreshCookie.HttpOnly {
		t.Error("expected refresh cookie to be HttpOnly")
	}

	var resp map[string]any
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	session, ok := resp["session"].(map[string]any)
	if !ok {
		t.Fatal("expected session object in response")
	}
	if session["id"] == "" {
		t.Error("expected session id")
	}
}

func TestRefresh_NoCookie(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	w := httptest.NewRecorder()
	th.handler.RefreshToken(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestRefresh_InvalidToken(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "goauth_refresh", Value: "garbage"})
	w := httptest.NewRecorder()
	th.handler.RefreshToken(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}

	// Cookies should be cleared on error
	for _, c := range res.Cookies() {
		if c.MaxAge != -1 {
			t.Errorf("expected cookie %s to be cleared, got max-age=%d", c.Name, c.MaxAge)
		}
	}
}

func TestRefresh_ClearsCookiesOnError(t *testing.T) {
	th := newTestHarness()

	// Register and then revoke the session to make refresh fail
	body := `{"email":"frank@example.com","password":"Passw0rd!","name":"Frank"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Register(w, req)

	var refreshToken, sessionToken string
	for _, c := range w.Result().Cookies() {
		switch c.Name {
		case "goauth_refresh":
			refreshToken = c.Value
		case "goauth_session":
			sessionToken = c.Value
		}
	}
	if refreshToken == "" {
		t.Fatal("no refresh cookie received")
	}

	// Revoke the session
	if err := th.handler.services.Session.Revoke(context.Background(), sessionToken); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req2.AddCookie(&http.Cookie{Name: "goauth_refresh", Value: refreshToken})
	w2 := httptest.NewRecorder()
	th.handler.RefreshToken(w2, req2)

	res := w2.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}

	// Cookies should be cleared on error
	clearedSession := false
	clearedRefresh := false
	for _, c := range res.Cookies() {
		if c.MaxAge == -1 {
			switch c.Name {
			case "goauth_session":
				clearedSession = true
			case "goauth_refresh":
				clearedRefresh = true
			}
		}
	}
	if !clearedSession {
		t.Error("expected session cookie to be cleared")
	}
	if !clearedRefresh {
		t.Error("expected refresh cookie to be cleared")
	}
}

func TestGetMe_NoUserInContext(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	w := httptest.NewRecorder()
	th.handler.GetMe(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestChangeName_NoUserInContext(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodPut, "/auth/name", strings.NewReader(`{"name":"New Name"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.ChangeName(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}
}

func TestRefreshToken_ExpiredRefreshCookie(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"alice@example.com","password":"Passw0rd!","name":"Alice"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Register(w, req)

	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Result().StatusCode)
	}

	// Use a garbage refresh token to simulate expired/invalid
	req2 := httptest.NewRequest(http.MethodPost, "/auth/refresh", nil)
	req2.AddCookie(&http.Cookie{Name: "goauth_refresh", Value: "expired-garbage"})
	w2 := httptest.NewRecorder()
	th.handler.RefreshToken(w2, req2)

	res := w2.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}

	// Cookies should be cleared on error
	for _, c := range res.Cookies() {
		if c.MaxAge != -1 {
			t.Errorf("expected cookie %s to be cleared, got max-age=%d", c.Name, c.MaxAge)
		}
	}
}

// AdminLogin always requires a second factor when a TwoFactorService is
// wired in (unconditionally, independent of RequireEmail2FA/per-user flags —
// see AuthService.AdminLogin), so this exercises the full challenge+verify
// round trip rather than expecting a session directly from AdminLogin.
func TestAdminLogin_SetsCookieAndHidesToken(t *testing.T) {
	th := newTestHarness()
	createAdminUser(t, th, "admin@example.com", "Passw0rd!")

	body := `{"email":"admin@example.com","password":"Passw0rd!"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/admin/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.AdminLogin(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var resp map[string]any
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["requiresTwoFactor"] != true {
		t.Fatalf("expected admin login to require two-factor, got %v", resp)
	}
	for _, c := range res.Cookies() {
		if c.Name == "goauth_session" {
			t.Fatal("must not set goauth_session before the second factor is verified")
		}
	}
	user, ok := resp["user"].(map[string]any)
	if !ok {
		t.Fatal("expected user object in response")
	}
	if user["role"] != "admin" {
		t.Errorf("expected admin role in response, got %v", user["role"])
	}
	challengeID, _ := resp["challengeId"].(string)
	if challengeID == "" {
		t.Fatal("expected a challengeId")
	}
	var bindingCookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == "_2fa_challenge" {
			bindingCookie = c
		}
	}
	if bindingCookie == nil {
		t.Fatal("expected a challenge binding cookie")
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
		t.Fatalf("expected verify to succeed, got %d", verifyRes.StatusCode)
	}

	var sessionCookie *http.Cookie
	for _, c := range verifyRes.Cookies() {
		if c.Name == "goauth_session" {
			sessionCookie = c
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("expected goauth_session cookie after completing admin two-factor verification")
	}
	if sessionCookie.Value == "" {
		t.Error("expected non-empty cookie value")
	}

	var verifyResp map[string]any
	if err := json.NewDecoder(verifyRes.Body).Decode(&verifyResp); err != nil {
		t.Fatal(err)
	}
	if tok, ok := verifyResp["sessionToken"]; ok && tok != "" {
		t.Errorf("sessionToken must not leak in JSON response body, got %v", tok)
	}
}

func TestAdminLogin_NonAdmin_Rejected(t *testing.T) {
	th := newTestHarness()
	sum := sha256.Sum256([]byte("Passw0rd!"))
	hash := hex.EncodeToString(sum[:])
	user := &domain.User{
		ID:           "user-id",
		Email:        "user@example.com",
		PasswordHash: &hash,
		Name:         "User",
		Role:         domain.RoleUser,
		IsVerified:   true,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := th.users.Create(context.Background(), user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	body := `{"email":"user@example.com","password":"Passw0rd!"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/admin/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.AdminLogin(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}

	var resp map[string]any
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] != "invalid_credentials" {
		t.Errorf("expected error invalid_credentials, got %v", resp["error"])
	}

	for _, c := range res.Cookies() {
		if c.Name == "goauth_session" && c.Value != "" {
			t.Error("must not set a session cookie for rejected admin login")
		}
	}
}

func TestAdminLogin_WrongPassword(t *testing.T) {
	th := newTestHarness()
	createAdminUser(t, th, "admin@example.com", "Passw0rd!")

	body := `{"email":"admin@example.com","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/admin/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.AdminLogin(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", res.StatusCode)
	}

	var resp map[string]any
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] != "invalid_credentials" {
		t.Errorf("expected error invalid_credentials, got %v", resp["error"])
	}
}

// GET /auth/me carries the caller's session alongside the user, which is the
// only way a client can read the active org: PUT/DELETE /auth/orgs/active
// answer with a bare {"message"} and nothing else exposes it.
func TestGetMe_IncludesSession(t *testing.T) {
	th := newTestHarness()

	orgID, orgRole := "org-1", "admin"
	user := &domain.User{ID: "u-1", Email: "a@b.c", Role: domain.RoleAdmin}
	session := &domain.Session{
		ID: "s-1", UserID: "u-1", TokenHash: "must-not-leak",
		RefreshTokenHash: "must-not-leak-either",
		ActiveOrgID:      &orgID, ActiveOrgRole: &orgRole,
	}

	ctx := middleware.ContextWithUser(context.Background(), user)
	ctx = middleware.ContextWithSession(ctx, session)

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	th.handler.GetMe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		ID      string `json:"id"`
		Session *struct {
			ID            string  `json:"id"`
			ActiveOrgID   *string `json:"activeOrgId"`
			ActiveOrgRole *string `json:"activeOrgRole"`
		} `json:"session"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding /auth/me: %v", err)
	}
	if resp.ID != "u-1" {
		t.Errorf("id = %q, want u-1", resp.ID)
	}
	if resp.Session == nil {
		t.Fatal("no session in the /auth/me payload")
	}
	if resp.Session.ActiveOrgID == nil || *resp.Session.ActiveOrgID != orgID {
		t.Errorf("activeOrgId = %v, want %q", resp.Session.ActiveOrgID, orgID)
	}
	if resp.Session.ActiveOrgRole == nil || *resp.Session.ActiveOrgRole != orgRole {
		t.Errorf("activeOrgRole = %v, want %q", resp.Session.ActiveOrgRole, orgRole)
	}

	// Session carries three token hashes. All are json:"-", and this endpoint
	// is the one place the struct is handed to an untrusted reader.
	if body := w.Body.String(); strings.Contains(body, "must-not-leak") {
		t.Errorf("a token hash reached the /auth/me body: %s", body)
	}
}

// A caller with no session in context (there is no such path through
// AuthMiddleware today) must still get a well-formed user rather than a nil
// dereference or a null session field.
func TestGetMe_OmitsSessionWhenAbsent(t *testing.T) {
	th := newTestHarness()

	user := &domain.User{ID: "u-1", Email: "a@b.c", Role: domain.RoleUser}
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil).
		WithContext(middleware.ContextWithUser(context.Background(), user))
	w := httptest.NewRecorder()
	th.handler.GetMe(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if strings.Contains(w.Body.String(), `"session"`) {
		t.Errorf("session should be omitted entirely, got %s", w.Body.String())
	}
}

// GET /auth/csrf-token stays a bare 204 unless a deployment opts in. The token
// is in the cookie; a client that can read it needs nothing in the body, and a
// value not in a body cannot be cached or logged by an intermediary.
func TestGetCSRFToken_204ByDefault(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/auth/csrf-token", nil).
		WithContext(middleware.ContextWithCSRFToken(context.Background(), "tok.sig"))
	w := httptest.NewRecorder()
	th.handler.GetCSRFToken(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if body := w.Body.String(); strings.Contains(body, "tok.sig") {
		t.Errorf("token leaked into the body without opting in: %s", body)
	}
}

// With ExposeCSRFTokenInBody the same route answers 200 {"token": ...} — the
// opt-in for a frontend on a different registrable domain, which cannot read
// the cookie however it is scoped.
func TestGetCSRFToken_BodyWhenExposed(t *testing.T) {
	th := newTestHarness()
	th.handler.csrfTokenCfg = &middleware.CSRFTokenConfig{ExposeCSRFTokenInBody: true}

	req := httptest.NewRequest(http.MethodGet, "/auth/csrf-token", nil).
		WithContext(middleware.ContextWithCSRFToken(context.Background(), "tok.sig"))
	w := httptest.NewRecorder()
	th.handler.GetCSRFToken(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding body: %v", err)
	}
	if resp["token"] != "tok.sig" {
		t.Errorf("token = %q, want tok.sig", resp["token"])
	}
	// A 200 with a body is cacheable where a 204 was not, and a shared cache
	// handing one visitor's token to the next would hand over a working one.
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// Opted in but the CSRF middleware isn't in front of this route: there is no
// token to hand back, and inventing one would hand out a value the cookie
// doesn't match.
func TestGetCSRFToken_NoTokenInContext(t *testing.T) {
	th := newTestHarness()
	th.handler.csrfTokenCfg = &middleware.CSRFTokenConfig{ExposeCSRFTokenInBody: true}

	w := httptest.NewRecorder()
	th.handler.GetCSRFToken(w, httptest.NewRequest(http.MethodGet, "/auth/csrf-token", nil))

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
}
