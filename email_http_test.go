package goauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/routes"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
)

type emailHTTPMailer struct {
	mu    sync.Mutex
	codes map[string]string
}

func (m *emailHTTPMailer) Send(_ context.Context, to, _, _, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.codes == nil {
		m.codes = map[string]string{}
	}
	for _, line := range strings.Split(text, "\n") {
		if len(strings.TrimSpace(line)) == 8 {
			m.codes[to] = strings.TrimSpace(line)
		}
	}
	return nil
}
func (m *emailHTTPMailer) code(email string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.codes[email]
}

func TestEmailChangeHTTPContract(t *testing.T) {
	mail := &emailHTTPMailer{}
	f := newAppHTTPFixture(t, true, false, WithMailer(mail), WithSecurity(SecurityConfig{AllowEmailChange: true}), WithRateLimitEnabled(false))
	created, err := f.a.Register(t.Context(), api.RegisterInput{Email: "email-http@example.com", Password: "Passw0rd!", Name: "Email Test"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.a.Trusted().Session.Create(t.Context(), api.CreateSessionInput{UserID: created.User.ID})
	if err != nil {
		t.Fatal(err)
	}
	adminContext, err := f.a.Trusted().Session.Create(sessioncontext.With(t.Context(), sessioncontext.Admin), api.CreateSessionInput{UserID: created.User.ID})
	if err != nil {
		t.Fatal(err)
	}
	if f.a.Trusted().Email == nil {
		t.Fatal("missing public capability")
	}
	for _, raw := range []string{`null`, `[]`, `{}`, `{"NewEmail":"new@example.com"}`, `{"newEmail":null}`, `{"newEmail":1}`, `{"newEmail":"new@example.com","userId":"injected"}`, `{"newEmail":"new@example.com","actor":{"userId":"injected"}}`, `{"newEmail":"a@example.com","newEmail":"b@example.com"}`, `{"newEmail":"new@example.com"} {}`, `{"newEmail":"new@example.com","password":"` + strings.Repeat("x", 5000) + `"}`} {
		t.Run("invalid input "+raw[:min(len(raw), 45)], func(t *testing.T) { f.request(t, "POST", "/auth/email/change/request", raw, created.SessionToken, 400) })
	}
	f.request(t, "POST", "/auth/email/change/request", `{"newEmail":"not-email","password":"Passw0rd!"}`, created.SessionToken, 400)
	f.request(t, "POST", "/auth/email/change/request", `{"newEmail":"new@example.com","password":"wrong"}`, created.SessionToken, 401)
	for _, test := range []struct {
		name, origin string
		token        bool
	}{{"missing CSRF", "http://localhost", false}, {"bad origin", "https://evil.invalid", true}} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/auth/email/change/request", strings.NewReader(`{"newEmail":"new@example.com","password":"Passw0rd!"}`))
			r.Header.Set("Origin", test.origin)
			r.AddCookie(&http.Cookie{Name: f.a.cookies.Name, Value: created.SessionToken, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			w := httptest.NewRecorder()
			f.mux.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("security boundary: %d %s", w.Code, w.Body.String())
			}
		})
	}
	w := f.request(t, "POST", "/auth/email/change/request", `{"newEmail":" NEW@example.com ","password":"Passw0rd!"}`, created.SessionToken, 200)
	var pending api.EmailChangeResult
	if err := json.Unmarshal(w.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	if pending.RequestID == "" || pending.ExpiresAt.IsZero() {
		t.Fatal("missing pending state")
	}
	var shape map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &shape); err != nil {
		t.Fatal(err)
	}
	if len(shape) != 2 {
		t.Fatalf("unexpected proof response: %s", w.Body.String())
	}
	body, _ := json.Marshal(map[string]string{"requestId": pending.RequestID, "currentEmailCode": mail.code(created.User.Email), "newEmailCode": mail.code("new@example.com")})
	f.request(t, "POST", "/auth/email/change/confirm", string(body), second.SessionToken, 400)
	f.request(t, "POST", "/auth/email/change/confirm", string(body), adminContext.SessionToken, 400)
	f.request(t, "POST", "/auth/email/change/resend", `{"requestId":"`+pending.RequestID+`","destination":"new"}`, created.SessionToken, 429)
	f.request(t, "GET", "/auth/me", "", created.SessionToken, 200)
	w = f.request(t, "POST", "/auth/email/change/confirm", string(body), created.SessionToken, 200)
	if !strings.Contains(w.Body.String(), `"step":"sign_in"`) {
		t.Fatalf("missing sign-in result: %s", w.Body.String())
	}
	cleared := map[string]bool{}
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			cleared[c.Name] = true
		}
	}
	if !cleared[f.a.cookies.Name] || !cleared[f.a.cookies.RefreshName] {
		t.Fatal("completion did not clear session cookies")
	}
	f.request(t, "GET", "/auth/me", "", second.SessionToken, 401)
	f.request(t, "GET", "/auth/me", "", adminContext.SessionToken, 401)
	if _, err := f.a.Login(t.Context(), api.LoginInput{Email: created.User.Email, Password: "Passw0rd!"}); err == nil {
		t.Fatal("old address still logs in")
	}
	if result, err := f.a.Login(t.Context(), api.LoginInput{Email: "new@example.com", Password: "Passw0rd!"}); err != nil || result.User.ID != created.User.ID {
		t.Fatalf("new address login: %v", err)
	}
}

func TestEmailChangeDisabledAndConfig(t *testing.T) {
	f := newAppHTTPFixture(t, true, false)
	if f.a.Trusted().Email != nil {
		t.Fatal("disabled capability is non-nil")
	}
	for _, pattern := range []string{routes.RequestEmailChange, routes.ConfirmEmailChange, routes.ResendEmailChange, routes.CancelEmailChange} {
		if _, ok := f.a.Handler(pattern); ok {
			t.Fatalf("disabled route: %s", pattern)
		}
	}
	if _, err := f.a.RequestEmailChange(t.Context(), api.RequestEmailChangeInput{}); err != domain.ErrEmailChangeDisabled {
		t.Fatalf("disabled facade: %v", err)
	}
	cfg := f.a.cfg.clone()
	cfg.mailer = nil
	cfg.email = nil
	cfg.registration.InviteSignup = false
	cfg.registration.RequireEmailVerification = false
	cfg.security.AllowEmailChange = true
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "email changes") {
		t.Fatalf("mailer not required: %v", err)
	}
}

func TestEmailChangeSecurityConfig(t *testing.T) {
	for _, test := range []struct {
		name string
		opts []Option
		want bool
	}{
		{name: "omitted defaults off"},
		{name: "explicitly enabled", opts: []Option{WithSecurity(SecurityConfig{AllowEmailChange: true})}, want: true},
		{name: "explicitly disabled", opts: []Option{WithSecurity(SecurityConfig{AllowEmailChange: false})}},
		{name: "later security section replaces earlier", opts: []Option{WithSecurity(SecurityConfig{AllowEmailChange: true}), WithSecurity(SecurityConfig{})}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := NewConfig(minimalOpts(test.opts...)...)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.security.AllowEmailChange != test.want || cfg.clone().security.AllowEmailChange != test.want {
				t.Fatal("security email-change setting was not preserved")
			}
		})
	}
}
