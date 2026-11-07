package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
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
		if data["verificationDelivery"] != "sent" {
			t.Fatalf("verification delivery status=%v, want sent", data["verificationDelivery"])
		}
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

func TestRegistrationVerificationDeliveryFailureAndDurableResend(t *testing.T) {
	var unavailable atomic.Bool
	unavailable.Store(true)
	mailer := &testutil.MockMailer{}
	f := newAppHTTPFixture(t, false, false,
		WithMailer(mailer),
		WithRegistration(RegistrationConfig{EmailPassword: true, AllowPublic: true, RequireEmailVerification: true}),
	)
	// Process the existing durable resend queue explicitly, avoiding timing
	// assumptions about its background polling interval.
	f.a.recoveryWorker.Stop()
	mailer.SendFn = func(_ context.Context, email, _, _, _ string) error {
		// A separate database read must see the committed user while SMTP is
		// running. This also catches holding SQLite's only connection in a tx.
		readCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		user, err := f.users.GetByEmail(readCtx, email)
		if err != nil || user == nil {
			t.Errorf("SMTP ran before account commit: account present=%v err=%v", user != nil, err)
		}
		if unavailable.Load() {
			return errors.New("private SMTP failure details")
		}
		return nil
	}
	const email = "delivery-pending@example.test"
	body := `{"email":"` + email + `","name":"Pending","password":"Passw0rd!"}`
	w := f.request(t, "POST", "/auth/register", body, "", http.StatusCreated)
	data := requireAuthenticationStep(t, w, api.StepVerifyEmail)
	if data["verificationDelivery"] != "failed" || !strings.Contains(data["message"].(string), "Account created") {
		t.Fatalf("signup failure state not explicit: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private SMTP") || strings.Contains(data["message"].(string), "email sent") {
		t.Fatal("response exposed delivery details or claimed successful sending")
	}
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == f.a.cookies.Name || cookie.Name == f.a.cookies.RefreshName {
			t.Fatal("pending signup issued credentials")
		}
	}
	userID := data["user"].(map[string]any)["id"].(string)
	var count int
	if err := f.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM users WHERE email=$1", email).Scan(&count); err != nil || count != 1 {
		t.Fatalf("committed account count=%d err=%v", count, err)
	}
	if err := f.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM sessions WHERE user_id=$1", userID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("pending session count=%d err=%v", count, err)
	}
	f.request(t, "POST", "/auth/register", body, "", http.StatusConflict)
	credentials := `{"email":"` + email + `","password":"Passw0rd!"}`
	requireAuthenticationStep(t, f.request(t, "POST", "/auth/login", credentials, "", http.StatusOK), api.StepVerifyEmail)
	// Public recovery remains account-independent and durable. A client need
	// not try registration again when the mail service is back.
	unavailable.Store(false)
	known := f.request(t, "POST", "/auth/verify-email/resend", `{"email":"`+email+`"}`, "", http.StatusOK)
	unknown := f.request(t, "POST", "/auth/verify-email/resend", `{"email":"unknown@example.test"}`, "", http.StatusOK)
	if known.Body.String() != unknown.Body.String() || strings.Contains(known.Body.String(), "verificationDelivery") {
		t.Fatal("public resend disclosed account-specific delivery state")
	}
	for range 2 {
		if processed, err := f.a.recoveryWorker.ProcessOne(t.Context()); !processed || err != nil {
			t.Fatalf("durable resend processed=%v err=%v", processed, err)
		}
	}
	code := testutil.GetLastVerificationCode(mailer)
	if code == "" {
		t.Fatal("recovery did not send a verification code")
	}
	requireAuthenticationStep(t, f.request(t, "POST", "/auth/verify-email", `{"code":"`+code+`"}`, "", http.StatusOK), api.StepSignIn)
	requireAuthenticationStep(t, f.request(t, "POST", "/auth/login", credentials, "", http.StatusOK), api.StepAuthenticated)
}

type registrationOutcomeProvider struct{}

func (registrationOutcomeProvider) Name() string { return "outcome" }

func (registrationOutcomeProvider) AuthURL(state, _ string) string {
	return "https://provider.example/authorize?state=" + url.QueryEscape(state)
}

func (registrationOutcomeProvider) Exchange(context.Context, string, string) (*port.OAuthProfile, error) {
	return &port.OAuthProfile{
		Provider: "outcome", ProviderUserID: "outcome-provider-user",
		Email: "oauth-delivery@example.test", Name: "OAuth signup", EmailVerified: false,
	}, nil
}

func TestOAuthVerificationDeliveryRedirectAndRecovery(t *testing.T) {
	mailer := &testutil.MockMailer{SendFn: func(context.Context, string, string, string, string) error {
		return errors.New("private SMTP failure details")
	}}
	f := newAppHTTPFixture(t, false, false,
		WithMailer(mailer), WithProvider(registrationOutcomeProvider{}),
		WithAuthentication(AuthenticationConfig{EmailPassword: true, OAuth: true}),
		WithRegistration(RegistrationConfig{OAuth: true, AllowPublic: true, RequireEmailVerification: true}),
	)
	callback := func(t *testing.T) *httptest.ResponseRecorder {
		t.Helper()
		initiation := f.request(t, "GET", "/auth/oauth/outcome", "", "", http.StatusOK)
		var started struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(initiation.Body.Bytes(), &started); err != nil {
			t.Fatal(err)
		}
		providerURL, err := url.Parse(started.URL)
		if err != nil {
			t.Fatal(err)
		}
		state := providerURL.Query().Get("state")
		if state == "" {
			t.Fatal("OAuth initiation omitted state")
		}
		r := httptest.NewRequest("GET", "/auth/oauth/outcome/callback?code=test&state="+url.QueryEscape(state), nil)
		for _, cookie := range initiation.Result().Cookies() {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		return w
	}
	for attempt := range 2 {
		t.Run(fmt.Sprintf("delivery failure %d", attempt), func(t *testing.T) {
			w := callback(t)
			location, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			query := location.Query()
			if w.Code != http.StatusFound || query.Get("step") != "verify_email" || query.Get("verificationDelivery") != "failed" || query.Get("error") != "" {
				t.Fatalf("OAuth callback reported signup failure: %d %s", w.Code, location)
			}
			if strings.Contains(location.String(), "private SMTP") {
				t.Fatal("OAuth redirect exposed delivery error details")
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == f.a.cookies.Name || cookie.Name == f.a.cookies.RefreshName {
					t.Fatal("pending OAuth signup issued credentials")
				}
			}
		})
	}
	var count int
	if err := f.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM users WHERE email=$1", "oauth-delivery@example.test").Scan(&count); err != nil || count != 1 {
		t.Fatalf("OAuth signup count=%d err=%v", count, err)
	}
	mailer.SendFn = nil
	w := callback(t)
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil || location.Query().Get("verificationDelivery") != "sent" {
		t.Fatalf("OAuth delivery did not resume: %s err=%v", w.Header().Get("Location"), err)
	}
	code := testutil.GetLastVerificationCode(mailer)
	requireAuthenticationStep(t, f.request(t, "POST", "/auth/verify-email", `{"code":"`+code+`"}`, "", http.StatusOK), api.StepSignIn)
	w = callback(t)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "step=authenticated") {
		t.Fatalf("verified OAuth login did not complete: %d %s", w.Code, w.Body.String())
	}
	foundSession := false
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == f.a.cookies.Name && cookie.Value != "" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Fatal("verified OAuth login did not issue its session cookie")
	}
}
