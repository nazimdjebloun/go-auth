package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// ForgotPassword starts a password reset.
func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Password.ForgotPassword(r.Context(), api.ForgotPasswordInput{Email: body.Email}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{
		"message": "If an account exists with this email, a reset link has been sent.",
	})
}

// ResetPassword completes a password reset.
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Password.ResetPassword(r.Context(), api.ResetPasswordInput{
		Code:        body.Code,
		NewPassword: body.NewPassword,
	}); err != nil {
		h.writeError(w, err)
		return
	}
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Password reset successfully"})
}

// ChangePassword changes the authenticated user's password.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	currentSession := middleware.GetSessionFromContext(r.Context())

	var body struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	input := api.ChangePasswordInput{
		UserID:      user.ID,
		OldPassword: body.OldPassword,
		NewPassword: body.NewPassword,
	}
	if currentSession != nil {
		input.ExceptSessionID = currentSession.ID
	}

	if err := h.services.Password.ChangePassword(r.Context(), input); err != nil {
		h.writeError(w, err)
		return
	}
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
}

// SetPasswordRequest starts password setup for the authenticated user.
func (h *Handler) SetPasswordRequest(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	if err := h.services.Password.RequestSetPassword(r.Context(), user.ID); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "If the email exists, a set password link has been sent."})
}

// SetPasswordConfirm completes password setup.
func (h *Handler) SetPasswordConfirm(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID      string `json:"userId"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Password.ConfirmSetPassword(r.Context(), api.ConfirmSetPasswordInput{
		UserID:      body.UserID,
		Code:        body.Code,
		NewPassword: body.NewPassword,
	}); err != nil {
		h.writeError(w, err)
		return
	}
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Password set successfully"})
}

// DeleteAccount deletes the authenticated user's account with a password.
func (h *Handler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var body struct {
		Password string `json:"password"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Auth.DeleteAccount(r.Context(), user.ID, body.Password); err != nil {
		h.writeError(w, err)
		return
	}
	middleware.ClearSessionCookie(w, h.cookies)
	middleware.ClearRefreshCookie(w, h.cookies)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Account deleted successfully"})
}

// RequestDeleteAccount starts email confirmation for account deletion.
func (h *Handler) RequestDeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	if err := h.services.Auth.RequestDeleteAccount(r.Context(), user.ID); err != nil {
		h.writeError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Deletion code sent to your email"})
}

// ConfirmDeleteAccount completes account deletion.
func (h *Handler) ConfirmDeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	// User ID always comes from the authenticated session — never from the body.
	if err := h.services.Auth.ConfirmDeleteAccount(r.Context(), api.ConfirmDeleteAccountInput{
		UserID: user.ID,
		Code:   body.Code,
	}); err != nil {
		h.writeError(w, err)
		return
	}

	middleware.ClearSessionCookie(w, h.cookies)
	middleware.ClearRefreshCookie(w, h.cookies)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Account deleted successfully"})
}
