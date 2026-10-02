package integration_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/api"
)

func TestAdminAccessRequiresVerifiedSessionAcrossLoginAndRefresh(t *testing.T) {
	for _, optOut := range []bool{false, true} {
		t.Run(map[bool]string{false: "required", true: "explicit opt-out"}[optOut], func(t *testing.T) {
			db, cleanup := newSQLiteDB(t)
			defer cleanup()
			migrateDB(t, db, "sqlite")
			mailer := &testMailer{}
			a, err := newTestAuth2FA(db, mailer, goauth.TwoFactorConfig{DisableAdminTwoFactor: optOut}, goauth.RegistrationConfig{
				EnableEmailPassword: true, AllowPublic: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			ctx := context.Background()
			registered, err := a.Register(ctx, api.RegisterInput{Email: "admin-mfa@test.com", Name: "Admin MFA", Password: validTestPassword()})
			if err != nil {
				t.Fatal(err)
			}
			if registered.Session.TwoFactorVerifiedAt != nil {
				t.Fatal("ordinary registration must not create second-factor assurance")
			}
			// Promotion does not turn an existing first-factor session into a
			// second-factor session. The current database role is checked per request.
			if _, err := db.Exec("UPDATE users SET role = 'admin' WHERE id = ?", registered.User.ID); err != nil {
				t.Fatal(err)
			}
			protected := a.RequireAuth(a.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})))
			checkAccess := func(raw string, allowed bool) {
				t.Helper()
				request := httptest.NewRequest(http.MethodGet, "/privileged", nil)
				request.AddCookie(&http.Cookie{
					Name: "goauth_session", Value: raw,
					Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
				})
				recorder := httptest.NewRecorder()
				protected.ServeHTTP(recorder, request)
				want := http.StatusForbidden
				if allowed {
					want = http.StatusNoContent
				}
				if recorder.Code != want || (!allowed && !strings.Contains(recorder.Body.String(), `"two_factor_required"`)) {
					t.Fatalf("admin access status=%d body=%s, want %d", recorder.Code, recorder.Body, want)
				}
			}
			checkAccess(registered.SessionToken, optOut)
			// Refreshing an unassured session also cannot upgrade its assurance.
			oldRefresh, err := a.Services().Session.RefreshSession(ctx, registered.RefreshToken)
			if err != nil || oldRefresh.Session.TwoFactorVerifiedAt != nil {
				t.Fatalf("old-session refresh manufactured assurance: %v, %v", oldRefresh, err)
			}
			checkAccess(oldRefresh.SessionToken, optOut)
			login, err := a.Login(ctx, api.LoginInput{Email: "admin-mfa@test.com", Password: validTestPassword()})
			if err != nil {
				t.Fatal(err)
			}
			if optOut {
				if login.RequiresTwoFactor || login.SessionToken == "" {
					t.Fatal("explicit opt-out did not allow password login")
				}
				checkAccess(login.SessionToken, true)
				return
			}
			if !login.RequiresTwoFactor || login.Session != nil || login.SessionToken != "" {
				t.Fatalf("ordinary admin login bypassed MFA: %+v", login)
			}
			code := extractCodeAfter(mailer.lastBody(), "Your code: ")
			verified, err := a.Services().TwoFactor.Verify(ctx, login.TwoFactorChallenge, login.BindingToken(), code, "", "")
			if err != nil || verified.Session.TwoFactorVerifiedAt == nil {
				t.Fatalf("verified login lacks assurance: %+v, %v", verified, err)
			}
			checkAccess(verified.SessionToken, true)
			refreshed, err := a.Services().Session.RefreshSession(ctx, verified.RefreshToken)
			if err != nil || refreshed.Session.TwoFactorVerifiedAt == nil {
				t.Fatalf("refresh lost assurance: %+v, %v", refreshed, err)
			}
			checkAccess(refreshed.SessionToken, true)
		})
	}
}
