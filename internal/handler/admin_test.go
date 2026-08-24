package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

// seedAdminActor seeds and returns an admin user — every admin handler now
// requires an authenticated admin actor in the request context, mirroring
// what RequireRole(domain.RoleAdmin) already enforces via Mount().
func seedAdminActor(t *testing.T, th *testHarness) *domain.User {
	t.Helper()
	actor := &domain.User{
		ID:         "actor-admin",
		Email:      "actor-admin@example.com",
		Name:       "Actor Admin",
		Role:       domain.RoleAdmin,
		IsVerified: true,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := th.users.Create(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	return actor
}

func TestAdminCreateUser(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	body := `{"email":"admin-created@example.com","password":"Passw0rd!","name":"Admin Created","role":"admin"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
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
	actor := seedAdminActor(t, th)

	body1 := `{"email":"dup@example.com","password":"Passw0rd!","name":"First"}`
	req1 := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	req1 = req1.WithContext(middleware.ContextWithUser(req1.Context(), actor))
	w1 := httptest.NewRecorder()
	th.handler.AdminCreateUser(w1, req1)
	if w1.Result().StatusCode != http.StatusCreated {
		t.Fatal("expected first create to succeed")
	}

	body2 := `{"email":"dup@example.com","password":"Passw0rd!","name":"Second"}`
	req2 := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	req2 = req2.WithContext(middleware.ContextWithUser(req2.Context(), actor))
	w2 := httptest.NewRecorder()
	th.handler.AdminCreateUser(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for duplicate email, got %d", res2.StatusCode)
	}
}

func TestAdminCreateUser_InvalidInput(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

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
			req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
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
	actor := seedAdminActor(t, th)

	body := `{"email":"sessions-test@example.com","password":"Passw0rd!","name":"Sessions Test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
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
	if err := th.sessions.Create(context.Background(), sess1); err != nil {
		t.Fatal(err)
	}
	if err := th.sessions.Create(context.Background(), sess2); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/admin/users/"+user.ID+"/sessions", nil)
	req2.SetPathValue("id", user.ID)
	req2 = req2.WithContext(middleware.ContextWithUser(req2.Context(), actor))
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
	actor := seedAdminActor(t, th)

	req := httptest.NewRequest(http.MethodGet, "/admin/users/nonexistent/sessions", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListUserSessions(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res.StatusCode)
	}
}

func TestAdminRevokeUserSession(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	body := `{"email":"revoke-test@example.com","password":"Passw0rd!","name":"Revoke Test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
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
	if err := th.sessions.Create(context.Background(), sess); err != nil {
		t.Fatal(err)
	}

	req2 := httptest.NewRequest(http.MethodDelete, "/admin/users/"+user.ID+"/sessions/revoke-sess-1", nil)
	req2.SetPathValue("id", user.ID)
	req2.SetPathValue("sessionId", "revoke-sess-1")
	req2 = req2.WithContext(middleware.ContextWithUser(req2.Context(), actor))
	w2 := httptest.NewRecorder()
	th.handler.AdminRevokeUserSession(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res2.StatusCode)
	}

	sessions, _ := th.sessions.ListAllByUserID(context.Background(), user.ID)
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after revoke, got %d", len(sessions))
	}
}

func TestAdminRevokeUserSession_NotFound(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	body := `{"email":"revoke-notfound@example.com","password":"Passw0rd!","name":"Revoke NotFound"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
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
	req2 = req2.WithContext(middleware.ContextWithUser(req2.Context(), actor))
	w2 := httptest.NewRecorder()
	th.handler.AdminRevokeUserSession(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", res2.StatusCode)
	}
}

func TestAdminBanUser(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	body := `{"email":"ban-me@example.com","password":"Passw0rd!","name":"Ban Me"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
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
	req2 = req2.WithContext(middleware.ContextWithUser(req2.Context(), actor))
	w2 := httptest.NewRecorder()
	th.handler.BanUser(w2, req2)

	res2 := w2.Result()
	if res2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res2.StatusCode)
	}

	updated, _ := th.users.GetByID(context.Background(), user.ID)
	if updated == nil || !updated.IsBanned {
		t.Error("expected user to be banned")
	}
}

func TestAdminUnbanUser(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	body := `{"email":"unban-me@example.com","password":"Passw0rd!","name":"Unban Me"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
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
	banReq = banReq.WithContext(middleware.ContextWithUser(banReq.Context(), actor))
	th.handler.BanUser(httptest.NewRecorder(), banReq)

	req3 := httptest.NewRequest(http.MethodPatch, "/admin/users/"+user.ID+"/unban", nil)
	req3.SetPathValue("id", user.ID)
	req3 = req3.WithContext(middleware.ContextWithUser(req3.Context(), actor))
	w3 := httptest.NewRecorder()
	th.handler.UnbanUser(w3, req3)

	res3 := w3.Result()
	if res3.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res3.StatusCode)
	}

	updated, _ := th.users.GetByID(context.Background(), user.ID)
	if updated == nil || updated.IsBanned {
		t.Error("expected user to be unbanned")
	}
}

// ─── GetAdminStats ───────────────────────────────────────────────────

func TestGetAdminStats_Unauthenticated(t *testing.T) {
	th := newTestHarness()
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	w := httptest.NewRecorder()
	th.handler.GetAdminStats(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestGetAdminStats_HappyPath(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	verified := &domain.User{ID: "u-verified", Email: "verified@example.com", IsVerified: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	banned := &domain.User{ID: "u-banned", Email: "banned@example.com", IsBanned: true, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	neverLoggedIn := &domain.User{ID: "u-fresh", Email: "fresh@example.com", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	for _, u := range []*domain.User{verified, banned, neverLoggedIn} {
		if err := th.users.Create(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.GetAdminStats(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var stats service.AdminStats
	if err := json.NewDecoder(res.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	// actor-admin + 3 seeded users.
	if stats.TotalUsers != 4 {
		t.Errorf("expected 4 total users, got %d", stats.TotalUsers)
	}
	// seedAdminActor's actor is also IsVerified:true, plus the seeded verified user.
	if stats.VerifiedUsers != 2 {
		t.Errorf("expected 2 verified users, got %d", stats.VerifiedUsers)
	}
	if stats.BannedUsers != 1 {
		t.Errorf("expected 1 banned user, got %d", stats.BannedUsers)
	}
	// None of the 4 users have ever logged in.
	if stats.NeverLoggedInUsers != 4 {
		t.Errorf("expected 4 never-logged-in users, got %d", stats.NeverLoggedInUsers)
	}
}

// ─── GetRegistrationTrend ──────────────────────────────────────────────

func TestGetRegistrationTrend_MissingParams(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	req := httptest.NewRequest(http.MethodGet, "/admin/stats/registrations", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.GetRegistrationTrend(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Result().StatusCode)
	}
}

func TestGetRegistrationTrend_HappyPath(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	today := time.Now().UTC()
	u := &domain.User{ID: "u-reg", Email: "reg@example.com", CreatedAt: today, UpdatedAt: today}
	if err := th.users.Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}

	from := today.Add(-24 * time.Hour).Format(time.RFC3339)
	to := today.Add(24 * time.Hour).Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/admin/stats/registrations?from="+from+"&to="+to, nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.GetRegistrationTrend(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body struct {
		Registrations []port.DailyCount `json:"registrations"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	var total int
	for _, c := range body.Registrations {
		total += c.Count
	}
	// actor-admin + u-reg, both created "today" and within the range.
	if total != 2 {
		t.Errorf("expected 2 registrations across buckets, got %d (%+v)", total, body.Registrations)
	}
}

// ─── GetLoginActivity ──────────────────────────────────────────────────

func TestGetLoginActivity_MissingParams(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	req := httptest.NewRequest(http.MethodGet, "/admin/stats/logins", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.GetLoginActivity(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Result().StatusCode)
	}
}

func TestGetLoginActivity_Global(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	now := time.Now().UTC()
	alice, bob := "user-alice", "user-bob"
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", ActorID: &alice, CreatedAt: now})
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", ActorID: &bob, CreatedAt: now})
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e3", Type: "login.failed", ActorID: &alice, CreatedAt: now})

	from := now.Add(-24 * time.Hour).Format(time.RFC3339)
	to := now.Add(24 * time.Hour).Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/admin/stats/logins?from="+from+"&to="+to, nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.GetLoginActivity(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body struct {
		Logins []port.DailyCount `json:"logins"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	var total int
	for _, c := range body.Logins {
		total += c.Count
	}
	// Only the two login.success events count — login.failed is excluded.
	if total != 2 {
		t.Errorf("expected 2 successful logins, got %d (%+v)", total, body.Logins)
	}
}

func TestGetLoginActivity_PerUser(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	now := time.Now().UTC()
	alice, bob := "user-alice", "user-bob"
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", ActorID: &alice, CreatedAt: now})
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", ActorID: &bob, CreatedAt: now})

	from := now.Add(-24 * time.Hour).Format(time.RFC3339)
	to := now.Add(24 * time.Hour).Format(time.RFC3339)
	req := httptest.NewRequest(http.MethodGet, "/admin/stats/logins?from="+from+"&to="+to+"&userId="+alice, nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.GetLoginActivity(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body struct {
		Logins []port.DailyCount `json:"logins"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	var total int
	for _, c := range body.Logins {
		total += c.Count
	}
	// Scoped to alice only — bob's login is excluded.
	if total != 1 {
		t.Errorf("expected 1 login for alice, got %d (%+v)", total, body.Logins)
	}
}
