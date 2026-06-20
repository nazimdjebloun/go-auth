package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

type mockUserRepo struct {
	mu    sync.Mutex
	users map[string]*domain.User
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{users: make(map[string]*domain.User)}
}

func (m *mockUserRepo) Create(_ context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.users[user.Email] = user
	return nil
}

func (m *mockUserRepo) GetByID(_ context.Context, id string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[email]
	if !ok {
		return nil, nil
	}
	return u, nil
}

func (m *mockUserRepo) Update(_ context.Context, user *domain.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[user.ID] = user
	m.users[user.Email] = user
	return nil
}

func (m *mockUserRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	if u != nil {
		delete(m.users, u.Email)
	}
	delete(m.users, id)
	return nil
}

func (m *mockUserRepo) List(_ context.Context, _ port.UserFilter) ([]domain.User, int, error) {
	return nil, 0, nil
}

type mockSessionRepo struct {
	mu       sync.Mutex
	sessions map[string]*domain.Session
	byID     map[string]*domain.Session
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{
		sessions: make(map[string]*domain.Session),
		byID:     make(map[string]*domain.Session),
	}
}

func (m *mockSessionRepo) Create(_ context.Context, s *domain.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.TokenHash] = s
	m.byID[s.ID] = s
	return nil
}

func (m *mockSessionRepo) GetByTokenHash(_ context.Context, hash string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[hash]
	if !ok {
		return nil, nil
	}
	return s, nil
}

func (m *mockSessionRepo) ListByUserID(_ context.Context, userID string) ([]domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var res []domain.Session
	for _, s := range m.byID {
		if s.UserID == userID {
			res = append(res, *s)
		}
	}
	return res, nil
}

func (m *mockSessionRepo) Delete(_ context.Context, tokenHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[tokenHash]
	if ok {
		delete(m.sessions, tokenHash)
		delete(m.byID, s.ID)
	}
	return nil
}

func (m *mockSessionRepo) DeleteByID(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if ok {
		delete(m.byID, id)
		delete(m.sessions, s.TokenHash)
	}
	return nil
}

func (m *mockSessionRepo) DeleteAllForUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.byID {
		if s.UserID == userID {
			delete(m.byID, k)
			delete(m.sessions, s.TokenHash)
		}
	}
	return nil
}

func (m *mockSessionRepo) DeleteAllForUserExcept(_ context.Context, userID string, exceptSessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.byID {
		if s.UserID == userID && s.ID != exceptSessionID {
			delete(m.byID, k)
			delete(m.sessions, s.TokenHash)
		}
	}
	return nil
}

func (m *mockSessionRepo) DeleteExpired(_ context.Context) error {
	return nil
}

type mockTokenRepo struct {
	mu     sync.Mutex
	tokens map[string]*domain.VerificationToken
}

func newMockTokenRepo() *mockTokenRepo {
	return &mockTokenRepo{tokens: make(map[string]*domain.VerificationToken)}
}

func (m *mockTokenRepo) Create(_ context.Context, t *domain.VerificationToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.ID] = t
	m.tokens[t.TokenHash] = t
	return nil
}

func (m *mockTokenRepo) GetByHash(_ context.Context, hash string) (*domain.VerificationToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[hash]
	if !ok {
		return nil, nil
	}
	return t, nil
}

func (m *mockTokenRepo) MarkUsed(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if ok {
		now := time.Now().UTC()
		t.UsedAt = &now
	}
	return nil
}

func (m *mockTokenRepo) DeleteExpired(_ context.Context) error {
	return nil
}

type mockTokenGen struct{}

func (m *mockTokenGen) Generate() (string, error) {
	b := sha256.Sum256([]byte(time.Now().String()))
	return hex.EncodeToString(b[:16]), nil
}

type mockHasher struct{}

func (m *mockHasher) Hash(password string) (string, error) {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:]), nil
}

func (m *mockHasher) Compare(password, hash string) error {
	sum := sha256.Sum256([]byte(password))
	if hex.EncodeToString(sum[:]) != hash {
		return domain.ErrInvalidCredentials
	}
	return nil
}

type testHarness struct {
	handler  *Handler
	users    *mockUserRepo
	sessions *mockSessionRepo
}

func newTestHarness() *testHarness {
	users := newMockUserRepo()
	sessions := newMockSessionRepo()
	tokens := newMockTokenRepo()
	hasher := &mockHasher{}
	gen := &mockTokenGen{}

	cfg := service.Config{
		AppName:     "TestApp",
		InviteTTL:   7 * 24 * time.Hour,
		SessionTTL:  30 * 24 * time.Hour,
		TokenTTL:    1 * time.Hour,
		BcryptCost:  4,
		TokenLength: 32,
	}

	sessCfg := service.DefaultSessionConfig()
	sessCfg.Duration = 30 * 24 * time.Hour
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	authSvc := service.NewAuthService(users, sessions, tokens, hasher, gen, nil, cfg, sessSvc)
	passSvc := service.NewPasswordService(users, tokens, hasher, gen, nil, sessions, cfg)
	verifySvc := service.NewVerificationService(users, tokens, gen, nil, cfg)
	inviteSvc := service.NewInviteService(users, sessions, nil, hasher, gen, nil, cfg, sessSvc)
	adminSvc := service.NewAdminService(users, sessions, hasher, cfg, sessSvc)

	h := New(Services{
		Auth:     authSvc,
		Password: passSvc,
		Session:  sessSvc,
		Verify:   verifySvc,
		Invite:   inviteSvc,
		Admin:    adminSvc,
	})
	return &testHarness{handler: h, users: users, sessions: sessions}
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

	// cookie is set
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

	// sessionToken is NOT in the response body
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

	// pre-register
	regBody := `{"email":"bob@example.com","password":"Passw0rd!","name":"Bob"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Register(w, req)

	// manually mark verified
	user, _ := th.users.GetByEmail(nil, "bob@example.com")
	if user != nil {
		user.IsVerified = true
	}

	// login
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

	// sessionToken not in body
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

	// register
	body := `{"email":"carol@example.com","password":"Passw0rd!","name":"Carol"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.Register(w, req)

	// extract token from cookie
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

	// logout with the cookie
	req2 := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	req2.Header.Set("Content-Type", "application/json")
	req2.AddCookie(&http.Cookie{Name: "goauth_session", Value: token})
	w2 := httptest.NewRecorder()
	th.handler.Logout(w2, req2)

	if w2.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Result().StatusCode)
	}

	// re-using the same token should fail
	_, err := th.handler.services.Session.Validate(nil, token)
	if err == nil {
		t.Fatal("expected session to be invalid after logout")
	}
}

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
	// password hash should NOT be exposed in JSON
	if user.PasswordHash != "" {
		t.Error("expected password hash to be omitted from JSON response")
	}
}

func TestAdminCreateUser_DuplicateEmail(t *testing.T) {
	th := newTestHarness()

	// Create first user
	body1 := `{"email":"dup@example.com","password":"Passw0rd!","name":"First"}`
	req1 := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	th.handler.AdminCreateUser(w1, req1)
	if w1.Result().StatusCode != http.StatusCreated {
		t.Fatal("expected first create to succeed")
	}

	// Try duplicate
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

	// Create a user first
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

	// Create sessions for this user
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

	// List sessions
	req2 := httptest.NewRequest(http.MethodGet, "/admin/users/"+user.ID+"/sessions", nil)
	req2.SetPathValue("id", user.ID)
	w2 := httptest.NewRecorder()
	th.handler.AdminListUserSessions(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res2.StatusCode)
	}

	var resp struct {
		Sessions []domain.Session `json:"sessions"`
	}
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

	// Create a user
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

	// Create a session
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

	// Revoke the session
	req2 := httptest.NewRequest(http.MethodDelete, "/admin/users/"+user.ID+"/sessions/revoke-sess-1", nil)
	req2.SetPathValue("id", user.ID)
	req2.SetPathValue("sessionId", "revoke-sess-1")
	w2 := httptest.NewRecorder()
	th.handler.AdminRevokeUserSession(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res2.StatusCode)
	}

	// Verify session is gone
	sessions, _ := th.sessions.ListByUserID(nil, user.ID)
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after revoke, got %d", len(sessions))
	}
}

func TestAdminRevokeUserSession_NotFound(t *testing.T) {
	th := newTestHarness()

	// Create a user
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

	// Try to revoke a non-existent session
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

	// Create a user
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

	// Ban the user
	req2 := httptest.NewRequest(http.MethodPatch, "/admin/users/"+user.ID+"/ban", nil)
	req2.SetPathValue("id", user.ID)
	w2 := httptest.NewRecorder()
	th.handler.BanUser(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res2.StatusCode)
	}

	// Verify user is banned in DB
	updated, _ := th.users.GetByID(nil, user.ID)
	if updated == nil || !updated.IsBanned {
		t.Error("expected user to be banned")
	}
}

func TestAdminUnbanUser(t *testing.T) {
	th := newTestHarness()

	// Create and ban a user
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

	// Ban
	banReq := httptest.NewRequest(http.MethodPatch, "/admin/users/"+user.ID+"/ban", nil)
	banReq.SetPathValue("id", user.ID)
	th.handler.BanUser(httptest.NewRecorder(), banReq)

	// Unban
	req3 := httptest.NewRequest(http.MethodPatch, "/admin/users/"+user.ID+"/unban", nil)
	req3.SetPathValue("id", user.ID)
	w3 := httptest.NewRecorder()
	th.handler.UnbanUser(w3, req3)

	res3 := w3.Result()
	if res3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res3.StatusCode)
	}

	// Verify user is no longer banned
	updated, _ := th.users.GetByID(nil, user.ID)
	if updated == nil || updated.IsBanned {
		t.Error("expected user to be unbanned")
	}
}
