package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func (h *OAuthHandlers) inviteBindingCookie(value string, maxAge int) *http.Cookie {
	name := "goauth_oauth_invite"
	if h.cookies.Secure {
		name = "__Host-" + name
	}
	cookie := &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: maxAge}
	cookie.Secure = h.cookies.Secure
	cookie.SameSite = h.cookies.SameSite
	return cookie
}

// InitiateInvite starts invited provider signup without opening public signup.
func (h *OAuthHandlers) InitiateInvite(w http.ResponseWriter, r *http.Request) {
	if h.disabled() {
		h.writeError(w, domain.ErrMethodDisabled)
		return
	}
	var body struct {
		InviteToken string `json:"inviteToken"`
	}
	if !(&Handler{log: h.log}).decodeJSON(w, r, &body) {
		return
	}
	flow, err := h.oauth.InitiateInvite(r.Context(), api.OAuthInviteInput{Provider: r.PathValue("provider"), InviteToken: body.InviteToken})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.setOAuthStateCookie(w, flow.State, 600)
	h.writeJSON(w, http.StatusOK, map[string]string{"url": flow.URL})
}

// VerifyInviteEmail completes address proof before creating an OAuth account.
func (h *OAuthHandlers) VerifyInviteEmail(w http.ResponseWriter, r *http.Request) {
	if h.disabled() {
		h.writeError(w, domain.ErrMethodDisabled)
		return
	}
	var body struct {
		ChallengeID string `json:"challengeId"`
		Code        string `json:"code"`
	}
	if !(&Handler{log: h.log}).decodeJSON(w, r, &body) {
		return
	}
	binding := ""
	if cookie, err := r.Cookie(h.inviteBindingCookie("", 0).Name); err == nil {
		binding = cookie.Value
	}
	result, err := h.oauth.VerifyInviteEmail(r.Context(), api.OAuthInviteVerifyInput{ChallengeID: body.ChallengeID, Code: body.Code, BindingToken: binding, IP: middleware.ClientIP(r, h.clientIP), UserAgent: r.UserAgent()})
	if err != nil {
		h.writeError(w, err)
		return
	}
	http.SetCookie(w, h.inviteBindingCookie("", -1))
	if result.RequiresTwoFactor {
		if h.twoFactor == nil {
			h.writeError(w, domain.ErrInternal)
			return
		}
		http.SetCookie(w, newBindingCookie(bindingCookieParams{name: h.challengeCookieName(r), value: result.BindingToken(), path: "/", secure: h.cookies.Secure, sameSite: h.cookies.SameSite, maxAge: int(h.twoFactor.CookieTTL().Seconds())}))
		h.writeJSON(w, http.StatusOK, map[string]any{"requiresTwoFactor": true, "challengeId": result.TwoFactorChallenge, "codeSent": result.CodeSent, "expiresAt": result.TwoFactorExpiresAt})
		return
	}
	if err := middleware.SetAuthenticationCookies(w, r, h.cookies, h.csrfTokenCfg, result.SessionID, result.SessionToken, result.RefreshToken); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]bool{"isNewUser": true})
}
