package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Password.ForgotPassword(r.Context(), service.ForgotPasswordInput{Email: body.Email}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "If an account exists with this email, a reset link has been sent.",
	})
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Password.ResetPassword(r.Context(), service.ResetPasswordInput{
		Code:        body.Code,
		NewPassword: body.NewPassword,
	}); err != nil {
		writeError(w, err)
		return
	}
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Password reset successfully"})
}

func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	currentSession := middleware.GetSessionFromContext(r.Context())

	var body struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	input := service.ChangePasswordInput{
		UserID:      user.ID,
		OldPassword: body.OldPassword,
		NewPassword: body.NewPassword,
	}
	if currentSession != nil {
		input.ExceptSessionID = currentSession.ID
	}

	if err := h.services.Password.ChangePassword(r.Context(), input); err != nil {
		writeError(w, err)
		return
	}
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

func (h *Handler) SetPasswordRequest(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	if err := h.services.Password.RequestSetPassword(r.Context(), user.ID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "If the email exists, a set password link has been sent."})
}

func (h *Handler) SetPasswordConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID      string `json:"userId"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Password.ConfirmSetPassword(r.Context(), service.ConfirmSetPasswordInput{
		UserID:      body.UserID,
		Code:        body.Code,
		NewPassword: body.NewPassword,
	}); err != nil {
		writeError(w, err)
		return
	}
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Password set successfully"})
}

func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
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

	if err := h.services.Auth.DeleteAccount(r.Context(), user.ID, body.Password); err != nil {
		writeError(w, err)
		return
	}
	middleware.ClearSessionCookie(w, h.services.Session.Config())
	middleware.ClearRefreshCookie(w, h.services.Session.Config())
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Account deleted successfully"})
}

func (h *Handler) RequestDeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	if err := h.services.Auth.RequestDeleteAccount(r.Context(), user.ID); err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Deletion code sent to your email"})
}

func (h *Handler) ConfirmDeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	// User ID always comes from the authenticated session — never from the body.
	if err := h.services.Auth.ConfirmDeleteAccount(r.Context(), service.ConfirmDeleteAccountInput{
		UserID: user.ID,
		Code:   body.Code,
	}); err != nil {
		writeError(w, err)
		return
	}

	middleware.ClearSessionCookie(w, h.services.Session.Config())
	middleware.ClearRefreshCookie(w, h.services.Session.Config())
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Account deleted successfully"})
}
