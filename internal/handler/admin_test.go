package handler

import (
	"context"
	"encoding/json"
	"fmt"
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

// ─── AdminListSessions ───────────────────────────────────────────────

func TestAdminListSessions(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	now := time.Now().UTC()
	th.sessions.Create(context.Background(), &domain.Session{
		ID: "s1", UserID: "user-1", TokenHash: "s1-token", IP: "1.1.1.1",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastActiveAt: now,
	})
	th.sessions.Create(context.Background(), &domain.Session{
		ID: "s2", UserID: "user-2", TokenHash: "s2-token", IP: "2.2.2.2",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastActiveAt: now,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListSessions(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body struct {
		Sessions []domain.Session `json:"sessions"`
		Total    int              `json:"total"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 {
		t.Errorf("expected 2 sessions, got %d", body.Total)
	}
}

func TestAdminListSessions_FilterByUserID(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	now := time.Now().UTC()
	th.sessions.Create(context.Background(), &domain.Session{
		ID: "s1", UserID: "user-1", TokenHash: "s1-token", IP: "1.1.1.1",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastActiveAt: now,
	})
	th.sessions.Create(context.Background(), &domain.Session{
		ID: "s2", UserID: "user-2", TokenHash: "s2-token", IP: "2.2.2.2",
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, LastActiveAt: now,
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions?userId=user-1", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListSessions(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body struct {
		Sessions []domain.Session `json:"sessions"`
		Total    int              `json:"total"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Sessions) != 1 || body.Sessions[0].UserID != "user-1" {
		t.Errorf("expected 1 session for user-1, got %+v", body)
	}
}

func TestAdminListSessions_Unauthenticated(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/admin/sessions", nil)
	w := httptest.NewRecorder()
	th.handler.AdminListSessions(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

// ─── Bulk user actions ─────────────────────────────────────────────

func TestBulkBanUsers(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	th.users.Create(context.Background(), &domain.User{ID: "user-1", Email: "u1@example.com"})
	th.users.Create(context.Background(), &domain.User{ID: "user-2", Email: "u2@example.com"})

	body := `{"userIds":["user-1","user-2","nonexistent"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users/bulk/ban", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.BulkBanUsers(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var result service.BulkUserActionResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result.Succeeded) != 2 {
		t.Errorf("expected 2 succeeded, got %+v", result.Succeeded)
	}
	if len(result.Failed) != 1 || result.Failed[0].UserID != "nonexistent" {
		t.Errorf("expected 1 failure for nonexistent, got %+v", result.Failed)
	}
}

func TestBulkBanUsers_Unauthenticated(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodPost, "/admin/users/bulk/ban", strings.NewReader(`{"userIds":["user-1"]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	th.handler.BulkBanUsers(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestBulkUnbanUsers(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	now := time.Now().UTC()
	th.users.Create(context.Background(), &domain.User{ID: "user-1", Email: "u1@example.com", IsBanned: true, BannedAt: &now})

	body := `{"userIds":["user-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users/bulk/unban", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.BulkUnbanUsers(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var result service.BulkUserActionResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result.Succeeded) != 1 {
		t.Errorf("expected 1 succeeded, got %+v", result.Succeeded)
	}
}

func TestBulkDeleteUsers(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	th.users.Create(context.Background(), &domain.User{ID: "user-1", Email: "u1@example.com"})

	body := `{"userIds":["user-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users/bulk/delete", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.BulkDeleteUsers(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var result service.BulkUserActionResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result.Succeeded) != 1 {
		t.Errorf("expected 1 succeeded, got %+v", result.Succeeded)
	}
}

func TestBulkRevokeUserSessions(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	th.users.Create(context.Background(), &domain.User{ID: "user-1", Email: "u1@example.com"})
	now := time.Now().UTC()
	th.sessions.Create(context.Background(), &domain.Session{
		ID: "s1", UserID: "user-1", TokenHash: "s1-token", ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})

	body := `{"userIds":["user-1"]}`
	req := httptest.NewRequest(http.MethodPost, "/admin/users/bulk/revoke-sessions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.BulkRevokeUserSessions(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var result service.BulkUserActionResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result.Succeeded) != 1 {
		t.Errorf("expected 1 succeeded, got %+v", result.Succeeded)
	}
}

// ─── AdminListAuditLogs / AdminListUserAuditLogs ────────────────────

func TestAdminListAuditLogs_MultiEventType(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	now := time.Now().UTC()
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", CreatedAt: now})
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.failed", CreatedAt: now})
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e3", Type: "logout", CreatedAt: now})

	req := httptest.NewRequest(http.MethodGet, "/admin/audit-logs?event_type=login.success,logout", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListAuditLogs(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body service.AdminListAuditLogsResult
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 2 {
		t.Errorf("expected 2 events, got %d: %+v", body.Total, body.Events)
	}
}

func TestAdminListAuditLogs_ActorEmail(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	th.users.Create(context.Background(), &domain.User{ID: "alice-id", Email: "alice@example.com"})
	alice := "alice-id"
	now := time.Now().UTC()
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", ActorID: &alice, CreatedAt: now})

	req := httptest.NewRequest(http.MethodGet, "/admin/audit-logs?actorEmail=alice@example.com", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListAuditLogs(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body service.AdminListAuditLogsResult
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 {
		t.Errorf("expected 1 event, got %d: %+v", body.Total, body.Events)
	}
}

func TestAdminListAuditLogs_ActorEmail_NotFound(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	req := httptest.NewRequest(http.MethodGet, "/admin/audit-logs?actorEmail=nobody@example.com", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListAuditLogs(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 user_not_found, got %d", w.Result().StatusCode)
	}
}

func TestAdminListUserAuditLogs_ScopesToPathUser(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	target, other := "target-id", "other-id"
	now := time.Now().UTC()
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", TargetUserID: &target, CreatedAt: now})
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e2", Type: "login.success", TargetUserID: &other, CreatedAt: now})

	req := httptest.NewRequest(http.MethodGet, "/admin/users/target-id/audit-logs", nil)
	req.SetPathValue("id", "target-id")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListUserAuditLogs(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body service.AdminListAuditLogsResult
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || body.Events[0].ID != "e1" {
		t.Errorf("expected 1 event for target-id, got %+v", body.Events)
	}
}

func TestAdminListAuditLogs_ResolvesEmails(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	th.users.Create(context.Background(), &domain.User{ID: "alice-id", Email: "alice@example.com"})
	alice := "alice-id"
	now := time.Now().UTC()
	th.auditLogs.AddEntry(port.AuditLogEntry{ID: "e1", Type: "login.success", ActorID: &alice, CreatedAt: now})

	req := httptest.NewRequest(http.MethodGet, "/admin/audit-logs", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListAuditLogs(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body service.AdminListAuditLogsResult
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if len(body.Events) != 1 || body.Events[0].ActorEmail == nil || *body.Events[0].ActorEmail != "alice@example.com" {
		t.Fatalf("expected 1 event with ActorEmail alice@example.com, got %+v", body.Events)
	}
}

func TestAdminListAuditLogs_Unauthenticated(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/admin/audit-logs", nil)
	w := httptest.NewRecorder()
	th.handler.AdminListAuditLogs(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

// ─── Admin — organizations ──────────────────────────────────────

func seedNonAdminActor(t *testing.T, th *testHarness) *domain.User {
	t.Helper()
	actor := &domain.User{
		ID:         "regular-user",
		Email:      "regular@example.com",
		Role:       domain.RoleUser,
		IsVerified: true,
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	if err := th.users.Create(context.Background(), actor); err != nil {
		t.Fatal(err)
	}
	return actor
}

func TestAdminListOrgs_HappyPath(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)
	owner := seedOrgUser(t, th)
	seedOrg(t, th, owner.ID)

	req := httptest.NewRequest(http.MethodGet, "/admin/orgs", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListOrgs(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body service.AdminListOrgsResult
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || len(body.Orgs) != 1 {
		t.Fatalf("expected exactly the one seeded org, got %+v", body)
	}
}

func TestAdminListOrgs_ActorNotAdmin_Forbidden(t *testing.T) {
	th := newTestHarness()
	actor := seedNonAdminActor(t, th)

	req := httptest.NewRequest(http.MethodGet, "/admin/orgs", nil)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListOrgs(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Result().StatusCode)
	}
}

func TestAdminListOrgs_Unauthenticated(t *testing.T) {
	th := newTestHarness()

	req := httptest.NewRequest(http.MethodGet, "/admin/orgs", nil)
	w := httptest.NewRecorder()
	th.handler.AdminListOrgs(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Result().StatusCode)
	}
}

func TestAdminGetOrg_HappyPath(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	req := httptest.NewRequest(http.MethodGet, "/admin/orgs/"+org.ID, nil)
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminGetOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var got domain.Organization
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.ID != org.ID {
		t.Errorf("expected org %s, got %s", org.ID, got.ID)
	}
}

func TestAdminGetOrg_NotFound(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	req := httptest.NewRequest(http.MethodGet, "/admin/orgs/bad-id", nil)
	req.SetPathValue("orgID", "bad-id")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminGetOrg(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Result().StatusCode)
	}
}

func TestAdminGetOrg_ActorNotAdmin_Forbidden(t *testing.T) {
	th := newTestHarness()
	actor := seedNonAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	req := httptest.NewRequest(http.MethodGet, "/admin/orgs/"+org.ID, nil)
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminGetOrg(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Result().StatusCode)
	}
}

func TestAdminListOrgMembers_HappyPath(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	req := httptest.NewRequest(http.MethodGet, "/admin/orgs/"+org.ID+"/members", nil)
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListOrgMembers(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	var body service.ListMembersResult
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 1 || body.Members[0].UserID != owner.ID {
		t.Fatalf("expected the one owner member, got %+v", body)
	}
}

func TestAdminListOrgMembers_ActorNotAdmin_Forbidden(t *testing.T) {
	th := newTestHarness()
	actor := seedNonAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	req := httptest.NewRequest(http.MethodGet, "/admin/orgs/"+org.ID+"/members", nil)
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminListOrgMembers(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Result().StatusCode)
	}
}

func TestAdminAddOrgMember_HappyPath(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)
	newMember := seedSecondUser(t, th)

	body := fmt.Sprintf(`{"userId":%q,"role":"member"}`, newMember.ID)
	req := httptest.NewRequest(http.MethodPost, "/admin/orgs/"+org.ID+"/members", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminAddOrgMember(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", res.StatusCode)
	}
	m, err := th.orgs.GetMembership(context.Background(), org.ID, newMember.ID)
	if err != nil || m == nil {
		t.Fatalf("expected new member to be added, got %+v, err=%v", m, err)
	}
}

func TestAdminAddOrgMember_ActorNotAdmin_Forbidden(t *testing.T) {
	th := newTestHarness()
	actor := seedNonAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)
	newMember := seedSecondUser(t, th)

	body := fmt.Sprintf(`{"userId":%q,"role":"member"}`, newMember.ID)
	req := httptest.NewRequest(http.MethodPost, "/admin/orgs/"+org.ID+"/members", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminAddOrgMember(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Result().StatusCode)
	}
}

func TestAdminDeleteOrg_HappyPath(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	req := httptest.NewRequest(http.MethodDelete, "/admin/orgs/"+org.ID, nil)
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminDeleteOrg(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	got, err := th.orgs.GetByID(context.Background(), org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("expected org to be deleted, still found: %+v", got)
	}
}

func TestAdminDeleteOrg_NotFound(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)

	req := httptest.NewRequest(http.MethodDelete, "/admin/orgs/bad-id", nil)
	req.SetPathValue("orgID", "bad-id")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminDeleteOrg(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Result().StatusCode)
	}
}

func TestAdminDeleteOrg_ActorNotAdmin_Forbidden(t *testing.T) {
	th := newTestHarness()
	actor := seedNonAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	req := httptest.NewRequest(http.MethodDelete, "/admin/orgs/"+org.ID, nil)
	req.SetPathValue("orgID", org.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminDeleteOrg(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Result().StatusCode)
	}
	// The org must survive a forbidden attempt.
	got, err := th.orgs.GetByID(context.Background(), org.ID)
	if err != nil || got == nil {
		t.Fatalf("expected org to still exist after a forbidden delete attempt, got %+v, err=%v", got, err)
	}
}

func TestAdminRemoveOrgMember_HappyPath(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)
	member := seedSecondUser(t, th)
	if err := th.orgs.AddMember(context.Background(), &domain.OrgMember{
		OrgID: org.ID, UserID: member.ID, Role: domain.OrgRoleMember, JoinedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/orgs/"+org.ID+"/members/"+member.ID, nil)
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("userID", member.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminRemoveOrgMember(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	m, err := th.orgs.GetMembership(context.Background(), org.ID, member.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m != nil {
		t.Errorf("expected member to be removed, still found: %+v", m)
	}
}

func TestAdminRemoveOrgMember_NotFound(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	req := httptest.NewRequest(http.MethodDelete, "/admin/orgs/"+org.ID+"/members/nobody", nil)
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("userID", "nobody")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminRemoveOrgMember(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Result().StatusCode)
	}
}

func TestAdminRemoveOrgMember_ActorNotAdmin_Forbidden(t *testing.T) {
	th := newTestHarness()
	actor := seedNonAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)
	member := seedSecondUser(t, th)
	if err := th.orgs.AddMember(context.Background(), &domain.OrgMember{
		OrgID: org.ID, UserID: member.ID, Role: domain.OrgRoleMember, JoinedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/orgs/"+org.ID+"/members/"+member.ID, nil)
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("userID", member.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminRemoveOrgMember(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Result().StatusCode)
	}
}

func TestAdminUpdateOrgMemberRole_HappyPath(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)
	member := seedSecondUser(t, th)
	if err := th.orgs.AddMember(context.Background(), &domain.OrgMember{
		OrgID: org.ID, UserID: member.ID, Role: domain.OrgRoleMember, JoinedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	body := `{"role":"admin"}`
	req := httptest.NewRequest(http.MethodPatch, "/admin/orgs/"+org.ID+"/members/"+member.ID+"/role", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("userID", member.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminUpdateOrgMemberRole(w, req)

	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	m, err := th.orgs.GetMembership(context.Background(), org.ID, member.ID)
	if err != nil || m == nil || m.Role != domain.OrgRoleAdmin {
		t.Fatalf("expected member to now be admin, got %+v, err=%v", m, err)
	}
}

func TestAdminUpdateOrgMemberRole_NotFound(t *testing.T) {
	th := newTestHarness()
	actor := seedAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)

	body := `{"role":"admin"}`
	req := httptest.NewRequest(http.MethodPatch, "/admin/orgs/"+org.ID+"/members/nobody/role", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("userID", "nobody")
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminUpdateOrgMemberRole(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Result().StatusCode)
	}
}

func TestAdminUpdateOrgMemberRole_ActorNotAdmin_Forbidden(t *testing.T) {
	th := newTestHarness()
	actor := seedNonAdminActor(t, th)
	owner := seedOrgUser(t, th)
	org := seedOrg(t, th, owner.ID)
	member := seedSecondUser(t, th)
	if err := th.orgs.AddMember(context.Background(), &domain.OrgMember{
		OrgID: org.ID, UserID: member.ID, Role: domain.OrgRoleMember, JoinedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	body := `{"role":"admin"}`
	req := httptest.NewRequest(http.MethodPatch, "/admin/orgs/"+org.ID+"/members/"+member.ID+"/role", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("orgID", org.ID)
	req.SetPathValue("userID", member.ID)
	req = req.WithContext(middleware.ContextWithUser(req.Context(), actor))
	w := httptest.NewRecorder()
	th.handler.AdminUpdateOrgMemberRole(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Result().StatusCode)
	}
}
