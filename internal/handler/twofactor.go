package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/middleware"
)

// VerifyTwoFactor completes any of the four gated flows above (Login,
// AdminLogin, Register, InviteRegister) — it doesn't need to know which one
// started the challenge.
func (h *Handler) VerifyTwoFactor(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeID string `json:"challengeId"`
		Code        string `json:"code"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.TwoFactor.Verify(
		r.Context(), body.ChallengeID, h.twoFactorBindingCookieValue(r), body.Code,
		extractIP(r.RemoteAddr), r.UserAgent(),
	)
	if err != nil {
		writeError(w, err)
		return
	}

	middleware.SetSessionCookie(w, h.services.Session.Config(), result.SessionToken)
	middleware.SetRefreshCookie(w, h.services.Session.Config(), result.RefreshToken)
	h.clearTwoFactorBindingCookie(w)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	writeJSON(w, http.StatusOK, map[string]any{"user": result.User, "session": result.Session})
}

// ResendTwoFactor refreshes the code on the caller's existing challenge. An
// unknown or binding-mismatched challenge gets the same generic 200 message
// as a real send — see TwoFactorService.Resend — so this handler doesn't
// special-case that path, it just forwards whatever error/status the service
// returns.
func (h *Handler) ResendTwoFactor(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ChallengeID string `json:"challengeId"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.TwoFactor.Resend(r.Context(), body.ChallengeID, h.twoFactorBindingCookieValue(r))
	if err != nil {
		writeError(w, err)
		return
	}

	h.setTwoFactorBindingCookie(w, result.BindingToken)
	writeJSON(w, http.StatusOK, map[string]any{
		"codeSent":    result.Sent,
		"expiresAt":   result.ExpiresAt,
		"challengeId": result.ID,
		"message":     "A new code has been sent",
	})
}

// Enable2FA turns on per-user 2FA for the authenticated caller.
// keepOtherSessions defaults to false (omitted = revoke) — see
// TwoFactorService.Enable for why the zero value has to be the safe one.
func (h *Handler) Enable2FA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	currentSession := middleware.GetSessionFromContext(r.Context())

	var body struct {
		Password          string `json:"password"`
		KeepOtherSessions bool   `json:"keepOtherSessions"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	callerSessionID := ""
	if currentSession != nil {
		callerSessionID = currentSession.ID
	}

	if err := h.services.TwoFactor.Enable(r.Context(), user.ID, body.Password, body.KeepOtherSessions, callerSessionID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Two-factor authentication enabled"})
}

// Disable2FA turns off per-user 2FA for the authenticated caller. No session
// revocation here — see TwoFactorService.Disable.
func (h *Handler) Disable2FA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.TwoFactor.Disable(r.Context(), user.ID, body.Password); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Two-factor authentication disabled"})
}
