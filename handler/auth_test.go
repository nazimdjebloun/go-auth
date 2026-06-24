package handler

import (
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

	user, _ := th.users.GetByEmail(nil, "bob@example.com")
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

	var token string
	for _, c := range w.Result().Cookies() {
		if c.Name == "goauth_session" {
			token = c.Value
			break
		}
	}
	if token == "" {
		t.Fatal("no session cookie received")
	}

	req2 := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "goauth_session", Value: token})
	w2 := httptest.NewRecorder()
	th.handler.Logout(w2, req2)

	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Result().StatusCode)
	}

	_, err := th.handler.services.Session.Validate(nil, token)
	if err == nil {
		t.Fatal("expected session to be invalid after logout")
	}
}
