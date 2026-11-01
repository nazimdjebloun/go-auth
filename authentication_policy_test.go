package goauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/provider/google"
)

func TestAuthenticationRegistrationDefaultsAndValidation(t *testing.T) {
	cfg, err := NewConfig(minimalOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.authentication.EmailPassword || cfg.authentication.OAuth || cfg.registration.AllowPublic || cfg.registration.EmailPassword || cfg.registration.OAuth || cfg.registration.InviteSignup {
		t.Fatalf("unexpected default policy: authentication=%+v registration=%+v", cfg.authentication, cfg.registration)
	}
	provider := WithProvider(google.New(google.Config{ClientID: "test", ClientSecret: "test", RedirectURL: "https://example.com/auth/oauth/google/callback"}))
	for _, tc := range []struct {
		name    string
		options []Option
		want    string
	}{
		{"no authentication", []Option{WithAuthentication(AuthenticationConfig{})}, "authentication"},
		{"OAuth without provider", []Option{WithAuthentication(AuthenticationConfig{OAuth: true})}, "WithProvider"},
		{"password signup disabled authentication", []Option{provider, WithAuthentication(AuthenticationConfig{OAuth: true}), WithRegistration(RegistrationConfig{EmailPassword: true})}, "authentication.EmailPassword"},
		{"OAuth signup disabled authentication", []Option{WithRegistration(RegistrationConfig{OAuth: true})}, "authentication.OAuth"},
		{"public signup without method", []Option{WithRegistration(RegistrationConfig{AllowPublic: true})}, "registration method"},
		{"invitation signup without method", []Option{WithRegistration(RegistrationConfig{InviteSignup: true})}, "registration method"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewConfig(minimalOpts(tc.options...)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	cfg, err = NewConfig(minimalOpts(provider, WithAuthentication(AuthenticationConfig{OAuth: true}), WithRegistration(RegistrationConfig{RequireEmailVerification: true}))...)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.authentication.EmailPassword {
		t.Fatal("explicit authentication choices were merged with defaults")
	}
}

func TestAuthenticationMethodsAndClosedSignupForExistingAccounts(t *testing.T) {
	ctx := context.Background()
	a := buildAuth(t, minimalOpts(WithBcryptCost(4))...)
	defer a.Close()
	registered, err := a.Register(ctx, api.RegisterInput{Email: "policy@example.com", Password: "Passw0rd!", Name: "Policy"})
	if err != nil {
		t.Fatal(err)
	}
	closed := a.cfg.clone()
	closed.registration = defaultRegistration()
	closed.set.registration = true
	b, err := New(&closed)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err = b.Login(ctx, api.LoginInput{Email: registered.User.Email, Password: "Passw0rd!"}); err != nil {
		t.Fatalf("closed signup blocked existing login: %v", err)
	}
	if _, err = b.Register(ctx, api.RegisterInput{Email: "new@example.com", Password: "Passw0rd!", Name: "New"}); !errors.Is(err, domain.ErrMethodDisabled) {
		t.Fatalf("closed signup: %v", err)
	}
	disabled := closed.clone()
	WithAuthentication(AuthenticationConfig{OAuth: true})(&disabled)
	WithProvider(google.New(google.Config{ClientID: "test", ClientSecret: "test", RedirectURL: "https://example.com/auth/oauth/google/callback"}))(&disabled)
	c, err := New(&disabled)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Login(ctx, api.LoginInput{Email: registered.User.Email, Password: "Passw0rd!"}); !errors.Is(err, domain.ErrMethodDisabled) {
		t.Fatalf("existing password login ignored policy: %v", err)
	}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"forgot", func() error { return c.Services().Password.ForgotPassword(ctx, api.ForgotPasswordInput{}) }},
		{"reset", func() error { return c.Services().Password.ResetPassword(ctx, api.ResetPasswordInput{}) }},
		{"request setup", func() error { return c.Services().Password.RequestSetPassword(ctx, registered.User.ID) }},
		{"confirm setup", func() error { return c.Services().Password.ConfirmSetPassword(ctx, api.ConfirmSetPasswordInput{}) }},
		{"change", func() error { return c.Services().Password.ChangePassword(ctx, api.ChangePasswordInput{}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, domain.ErrMethodDisabled) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestVerificationPolicyRestrictsExistingSessionsAndRefresh(t *testing.T) {
	ctx := context.Background()
	mailer := &testutil.MockMailer{}
	a := buildAuth(t, minimalOpts(WithBcryptCost(4), WithMailer(mailer))...)
	defer a.Close()
	reg, err := a.Register(ctx, api.RegisterInput{Email: "verify-policy@example.com", Password: "Passw0rd!", Name: "Verify"})
	if err != nil {
		t.Fatal(err)
	}
	enabled := a.cfg.clone()
	enabled.registration.RequireEmailVerification = true
	b, err := New(&enabled)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	request := func(auth *Auth, path, raw string) *httptest.ResponseRecorder {
		mux := http.NewServeMux()
		auth.Mount(mux)
		mux.Handle("GET /private", auth.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
		r := httptest.NewRequest(http.MethodGet, "https://example.com"+path, nil)
		r.AddCookie(&http.Cookie{Name: auth.cfg.browser.Cookies.Name, Value: raw, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := request(a, "/private", reg.SessionToken); w.Code != http.StatusNoContent {
		t.Fatalf("disabled requirement: %d %s", w.Code, w.Body.String())
	}
	if w := request(b, "/private", reg.SessionToken); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "email_not_verified") {
		t.Fatalf("existing session escaped restriction: %d %s", w.Code, w.Body.String())
	}
	w := request(b, "/auth/me", reg.SessionToken)
	var status map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || status["requiresVerification"] != true || status["email"] != reg.User.Email || status["role"] != nil || status["session"] != nil {
		t.Fatalf("pending status leaked protected data: %d %s", w.Code, w.Body.String())
	}
	if _, _, err := b.GetSession(ctx, reg.SessionToken); !errors.Is(err, domain.ErrEmailNotVerified) {
		t.Fatalf("direct validation bypassed restriction: %v", err)
	}
	refreshed, err := b.Services().Session.RefreshSession(ctx, reg.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(b, "/private", refreshed.SessionToken); w.Code != http.StatusForbidden {
		t.Fatalf("refresh bypassed restriction: %d", w.Code)
	}
	if w := request(a, "/private", refreshed.SessionToken); w.Code != http.StatusNoContent {
		t.Fatalf("turning requirement off did not restore access: %d", w.Code)
	}
	if _, err := b.Services().Verify.ResendVerification(ctx, reg.User.ID); err != nil {
		t.Fatal(err)
	}
	code := testutil.GetLastVerificationCode(mailer)
	if code == "" {
		t.Fatal("missing verification code")
	}
	if _, err := b.Services().Verify.VerifyEmail(ctx, code); err != nil {
		t.Fatal(err)
	}
	if w := request(b, "/private", refreshed.SessionToken); w.Code != http.StatusNoContent {
		t.Fatalf("verification did not restore same session: %d %s", w.Code, w.Body.String())
	}
}
