package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// VerifyEmail confirms a user's email address.
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	user, err := h.services.Verify.VerifyEmail(r.Context(), body.Code)
	if err != nil {
		h.writeError(w, err)
		return
	}

	sessResult, sessionErr := h.services.Session.Create(r.Context(), user.ID, h.ip(r), r.UserAgent())
	if sessionErr != nil {
		h.log.Error("failed to create session after verification", "err", sessionErr, "user_id", user.ID)
		h.writeError(w, domain.ErrInternal)
		return
	}

	middleware.SetSessionCookie(w, h.cookies, sessResult.SessionToken)
	middleware.SetRefreshCookie(w, h.cookies, sessResult.RefreshToken)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":    user,
		"session": sessResult.Session,
	})
}

// ResendVerification sends verification email to the authenticated user.
func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeError(w, domain.NewError("forbidden", "Not authenticated"))
		return
	}

	result, err := h.services.Verify.ResendVerification(r.Context(), user.ID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	// codeSent distinguishes a fresh send from a still-valid code left in
	// place, the same way the 2FA challenge response does — without it a
	// deliberate skip and a dead mailer are the same 200 to the client.
	message := "A verification code was already sent, check your email"
	if result.Sent {
		message = "Verification email sent"
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"codeSent":  result.Sent,
		"expiresAt": result.ExpiresAt,
		"message":   message,
	})
}

// ResendVerificationPublic sends verification email by address.
func (h *Handler) ResendVerificationPublic(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	// Both return values are dropped deliberately: this endpoint is
	// unauthenticated, so the error distinguishes "no such account" and Sent
	// distinguishes "already had a live code" — each of which would turn the
	// flat reply below into an account-existence oracle. The authenticated
	// ResendVerification above is where codeSent is safe to expose.
	_, _ = h.services.Verify.SendVerificationByEmail(r.Context(), body.Email)

	h.writeJSON(w, http.StatusOK, map[string]string{"message": "If an account exists, a verification email has been sent"})
}
