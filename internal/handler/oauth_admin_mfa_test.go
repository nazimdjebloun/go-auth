package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestOAuthAdminCallbackSetsBindingCookieWithoutIssuingSession(t *testing.T) {
	h := newOAuthTestHarness(t)
	ctx := context.Background()
	user := &domain.User{ID: "oauth-admin", Email: h.mockProvider.profile.Email, Role: domain.RoleAdmin, IsVerified: true}
	if err := h.userRepo.Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	if err := h.providerRepo.Create(ctx, &domain.ProviderAccount{ID: "identity", UserID: user.ID, Provider: "test", ProviderUserID: h.mockProvider.profile.ProviderUserID}); err != nil {
		t.Fatal(err)
	}
	cfg := service.Config{
		TwoFactorCodeTTL: 5 * time.Minute, TwoFactorChallengeCookieName: "_2fa_challenge",
		OTPPepper:           []byte("test-otp-pepper-32-bytes-long!!!"),
		TwoFactorBindingKey: []byte("test-binding-key-32-bytes-long!!"),
	}
	twoFactor := service.NewTwoFactorService(h.userRepo, h.sessionRepo, h.tokenRepo, &mockHasher{}, &testutil.MockMailer{}, nil, cfg, h.sessionSvc)
	h.oauthSvc.AttachTwoFactor(twoFactor)
	h.oauthHandlers.AttachTwoFactor(twoFactor)
	state := h.createStateToken(t, "admin-state")
	request := httptest.NewRequest(http.MethodGet, "/auth/oauth/test/callback?code=code&state="+state, nil)
	request.SetPathValue("provider", "test")
	recorder := httptest.NewRecorder()
	h.callback(recorder, request)
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil || recorder.Code != http.StatusFound || location.Query().Get("requiresTwoFactor") != "true" || location.Query().Get("challengeId") == "" {
		t.Fatalf("callback did not redirect to MFA: status=%d location=%v err=%v", recorder.Code, location, err)
	}
	var binding string
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == h.oauthHandlers.cookies.Name || cookie.Name == h.oauthHandlers.cookies.RefreshName {
			t.Fatal("callback set a session cookie before MFA")
		}
		if cookie.Name == cfg.TwoFactorChallengeCookieName {
			if !cookie.HttpOnly {
				t.Fatal("binding cookie must be HttpOnly")
			}
			binding = cookie.Value
		}
	}
	if binding == "" || strings.Contains(location.String(), binding) || strings.Contains(recorder.Body.String(), binding) {
		t.Fatal("binding credential must exist only in the cookie")
	}
}
