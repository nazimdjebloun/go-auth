package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

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

func TestCheckAuth_ValidSession(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"alice@example.com","password":"Passw0rd!","name":"Alice"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Register(w, req)

	var token string
	for _, c := range w.Result().Cookies() {
		if c.Name == "goauth_session" {
			token = c.Value
			break
		}
	}

	req2 := httptest.NewRequest(http.MethodGet, "/auth/check", nil)
	req2.AddCookie(&http.Cookie{Name: "goauth_session", Value: token})
	w2 := httptest.NewRecorder()
	th.handler.CheckAuth(w2, req2)

	res := w2.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var resp map[string]any
	json.NewDecoder(res.Body).Decode(&resp)
	if resp["user"] == nil {
		t.Fatal("expected user to be present")
	}
}

func TestCheckAuth_InvalidSession(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/auth/check", nil)
	req.AddCookie(&http.Cookie{Name: "goauth_session", Value: "garbage"})
	w := httptest.NewRecorder()
	th.handler.CheckAuth(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var resp map[string]any
	json.NewDecoder(res.Body).Decode(&resp)
	if resp["user"] != nil {
		t.Fatal("expected user to be nil")
	}
}

func TestCheckAuth_NoCookie(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/auth/check", nil)
	w := httptest.NewRecorder()
	th.handler.CheckAuth(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	var resp map[string]any
	json.NewDecoder(res.Body).Decode(&resp)
	if resp["user"] != nil {
		t.Fatal("expected user to be nil")
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
