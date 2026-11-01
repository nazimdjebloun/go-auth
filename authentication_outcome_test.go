package goauth

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"golang.org/x/crypto/bcrypt"
)

func requireAuthenticationStep(t *testing.T, w *httptest.ResponseRecorder, step api.AuthStep) map[string]any {
	t.Helper()
	var data map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	if data["step"] != string(step) {
		t.Fatalf("expected %s, got %s", step, w.Body.String())
	}
	for _, field := range []string{"requiresVerification", "requiresTwoFactor", "requiresInviteVerification", "sessionToken", "refreshToken", "bindingToken"} {
		if _, exists := data[field]; exists {
			t.Fatalf("obsolete or secret field %q in outcome", field)
		}
	}
	return data
}

func TestAuthenticationOutcomePasswordAndExistingVerificationSession(t *testing.T) {
	mailer := &testutil.MockMailer{}
	f := newAppHTTPFixture(t, false, false, WithMailer(mailer), WithRegistration(RegistrationConfig{EmailPassword: true, AllowPublic: true, RequireEmailVerification: true}))
	for _, existingSession := range []bool{false, true} {
		email := "fresh@example.test"
		if existingSession {
			email = "existing@example.test"
		}
		body := `{"email":"` + email + `","name":"Flow","password":"Passw0rd!"}`
		data := requireAuthenticationStep(t, f.request(t, "POST", "/auth/register", body, "", 201), api.StepVerifyEmail)
		userID := data["user"].(map[string]any)["id"].(string)
		credentials := `{"email":"` + email + `","password":"Passw0rd!"}`
		requireAuthenticationStep(t, f.request(t, "POST", "/auth/login", credentials, "", 200), api.StepVerifyEmail)
		code := testutil.GetLastVerificationCode(mailer)
		if code == "" {
			t.Fatal("verification email missing")
		}
		token := f.token // A different signed-in account must not count as this user's session.
		want := api.StepSignIn
		if existingSession {
			session, err := f.a.Services().Session.Create(t.Context(), api.CreateSessionInput{UserID: userID})
			if err != nil {
				t.Fatal(err)
			}
			token, want = session.SessionToken, api.StepAuthenticated
		}
		requireAuthenticationStep(t, f.request(t, "POST", "/auth/verify-email", `{"code":"`+code+`"}`, token, 200), want)
		requireAuthenticationStep(t, f.request(t, "POST", "/auth/login", credentials, "", 200), api.StepAuthenticated)
		if existingSession {
			requireAuthenticationStep(t, f.request(t, "GET", "/auth/me", "", token, 200), api.StepAuthenticated)
		}
	}
}

func TestAuthenticationOutcomeUnverifiedAdminDoesNotIssueSession(t *testing.T) {
	f := newAppHTTPFixture(t, false, false, WithRegistration(RegistrationConfig{RequireEmailVerification: true}))
	hash, err := bcrypt.GenerateFromPassword([]byte("Passw0rd!"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET password_hash=$1,is_verified=false WHERE id=$2", string(hash), f.admin.UserID); err != nil {
		t.Fatal(err)
	}
	user, err := f.users.GetByID(t.Context(), f.admin.UserID)
	if err != nil {
		t.Fatal(err)
	}
	w := f.request(t, "POST", "/auth/admin/login", `{"email":"`+user.Email+`","password":"Passw0rd!"}`, "", 200)
	requireAuthenticationStep(t, w, api.StepVerifyEmail)
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == f.a.cookies.AdminName || cookie.Name == f.a.cookies.AdminRefreshName {
			t.Fatal("unverified admin received credentials")
		}
	}
}
