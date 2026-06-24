package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

func TestAdminCreateUser(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"admin-created@example.com","password":"Passw0rd!","name":"Admin Created","role":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.AdminCreateUser(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", res.StatusCode)
	}

	var user domain.User
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	if user.Email != "admin-created@example.com" {
		t.Errorf("expected email admin-created@example.com, got %s", user.Email)
	}
	if user.Name != "Admin Created" {
		t.Errorf("expected name Admin Created, got %s", user.Name)
	}
	if !user.IsVerified {
		t.Error("expected admin-created user to be auto-verified")
	}
	if user.Role != domain.RoleAdmin {
		t.Errorf("expected role admin, got %s", user.Role)
	}
	if user.PasswordHash != nil {
		t.Error("expected password hash to be omitted from JSON response")
	}
}

func TestAdminCreateUser_DuplicateEmail(t *testing.T) {
	th := newTestHarness()

	body1 := `{"email":"dup@example.com","password":"Passw0rd!","name":"First"}`
	req1 := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	th.handler.AdminCreateUser(w1, req1)
	if w1.Result().StatusCode != http.StatusCreated {
		t.Fatal("expected first create to succeed")
	}

	body2 := `{"email":"dup@example.com","password":"Passw0rd!","name":"Second"}`
	req2 := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	th.handler.AdminCreateUser(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate email, got %d", res2.StatusCode)
	}
}

func TestAdminCreateUser_InvalidInput(t *testing.T) {
	th := newTestHarness()

	tests := []struct {
		name string
		body string
		code int
	}{
		{"missing email", `{"password":"Passw0rd!","name":"No Email"}`, 400},
		{"missing password", `{"email":"no-pass@example.com","name":"No Pass"}`, 400},
		{"weak password", `{"email":"weak@example.com","password":"short","name":"Weak"}`, 400},
		{"missing name", `{"email":"noname@example.com","password":"Passw0rd!"}`, 400},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			th.handler.AdminCreateUser(w, req)

			res := w.Result()
			if res.StatusCode != tc.code {
				t.Errorf("expected %d, got %d", tc.code, res.StatusCode)
			}
		})
	}
}

func TestAdminListUserSessions(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"sessions-test@example.com","password":"Passw0rd!","name":"Sessions Test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.AdminCreateUser(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("AdminCreateUser: expected 201, got %d", res.StatusCode)
	}

	var user domain.User
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	if user.ID == "" {
		t.Fatal("expected non-empty user ID")
	}

	sess1 := &domain.Session{
		ID:        "sess-1",
		UserID:    user.ID,
		TokenHash: "hash1",
		IP:        "192.168.1.1",
		UserAgent: "TestAgent/1.0",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	sess2 := &domain.Session{
		ID:        "sess-2",
		UserID:    user.ID,
		TokenHash: "hash2",
		IP:        "10.0.0.1",
		UserAgent: "TestAgent/2.0",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := th.sessions.Create(nil, sess1); err != nil {
		t.Fatal(err)
	}
	if err := th.sessions.Create(nil, sess2); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/admin/users/"+user.ID+"/sessions", nil)
	req2.SetPathValue("id", user.ID)
	w2 := httptest.NewRecorder()
	th.handler.AdminListUserSessions(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res2.StatusCode)
	}

	type respSessions struct {
		Sessions []domain.Session `json:"sessions"`
	}
	var resp respSessions
	if err := json.NewDecoder(res2.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(resp.Sessions))
	}
}

func TestAdminListUserSessions_NoUser(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/admin/users/nonexistent/sessions", nil)
	w := httptest.NewRecorder()
	th.handler.AdminListUserSessions(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestAdminRevokeUserSession(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"revoke-test@example.com","password":"Passw0rd!","name":"Revoke Test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.AdminCreateUser(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("AdminCreateUser: expected 201, got %d", res.StatusCode)
	}

	var user domain.User
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	sess := &domain.Session{
		ID:        "revoke-sess-1",
		UserID:    user.ID,
		TokenHash: "revoke-hash",
		IP:        "1.2.3.4",
		UserAgent: "RevokeAgent",
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := th.sessions.Create(nil, sess); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest(http.MethodDelete, "/admin/users/"+user.ID+"/sessions/revoke-sess-1", nil)
	req2.SetPathValue("id", user.ID)
	req2.SetPathValue("sessionId", "revoke-sess-1")
	w2 := httptest.NewRecorder()
	th.handler.AdminRevokeUserSession(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res2.StatusCode)
	}

	sessions, _ := th.sessions.ListByUserID(nil, user.ID)
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after revoke, got %d", len(sessions))
	}
}

func TestAdminRevokeUserSession_NotFound(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"revoke-notfound@example.com","password":"Passw0rd!","name":"Revoke NotFound"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.AdminCreateUser(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("AdminCreateUser: expected 201, got %d", res.StatusCode)
	}

	var user domain.User
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	req2 := httptest.NewRequest(http.MethodDelete, "/admin/users/"+user.ID+"/sessions/no-such-session", nil)
	req2.SetPathValue("id", user.ID)
	req2.SetPathValue("sessionId", "no-such-session")
	w2 := httptest.NewRecorder()
	th.handler.AdminRevokeUserSession(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res2.StatusCode)
	}
}

func TestAdminBanUser(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"ban-me@example.com","password":"Passw0rd!","name":"Ban Me"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.AdminCreateUser(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(res.Body)
		t.Fatalf("AdminCreateUser: expected 201, got %d, body=%s", res.StatusCode, string(bodyBytes))
	}

	var user domain.User
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	req2 := httptest.NewRequest(http.MethodPatch, "/admin/users/"+user.ID+"/ban", nil)
	req2.SetPathValue("id", user.ID)
	w2 := httptest.NewRecorder()
	th.handler.BanUser(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res2.StatusCode)
	}

	updated, _ := th.users.GetByID(nil, user.ID)
	if updated == nil || !updated.IsBanned {
		t.Error("expected user to be banned")
	}
}

func TestAdminUnbanUser(t *testing.T) {
	th := newTestHarness()

	body := `{"email":"unban-me@example.com","password":"Passw0rd!","name":"Unban Me"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.AdminCreateUser(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("AdminCreateUser: expected 201, got %d", res.StatusCode)
	}

	var user domain.User
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	banReq := httptest.NewRequest(http.MethodPatch, "/admin/users/"+user.ID+"/ban", nil)
	banReq.SetPathValue("id", user.ID)
	th.handler.BanUser(httptest.NewRecorder(), banReq)

	req3 := httptest.NewRequest(http.MethodPatch, "/admin/users/"+user.ID+"/unban", nil)
	req3.SetPathValue("id", user.ID)
	w3 := httptest.NewRecorder()
	th.handler.UnbanUser(w3, req3)

	res3 := w3.Result()
	if res3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res3.StatusCode)
	}

	updated, _ := th.users.GetByID(nil, user.ID)
	if updated == nil || updated.IsBanned {
		t.Error("expected user to be unbanned")
	}
}
