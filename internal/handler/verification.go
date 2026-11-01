package handler

import (
	"errors"
	"net/http"

	"github.com/nazimdjebloun/go-auth/api"
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
	activeUserID, err := h.verificationSessionUserID(r)
	if err != nil {
		h.writeError(w, err)
		return
	}

	user, err := h.services.Verify.VerifyEmail(r.Context(), body.Code)
	if err != nil {
		h.writeError(w, err)
		return
	}

	step := api.StepSignIn
	if user != nil && user.ID == activeUserID {
		step = api.StepAuthenticated
	}
	h.writeJSON(w, http.StatusOK, api.AuthenticationResponse{Step: step, User: user})
}

// Check an optional existing session before consuming the one-time code. A
// backend failure must not consume the code and then masquerade as logged out.
// A fresh signup still needs login; verifying email never issues credentials.
func (h *Handler) verificationSessionUserID(r *http.Request) (string, error) {
	cookie, err := r.Cookie(h.cookies.ForRequest(r).Name)
	if err != nil || cookie.Value == "" {
		return "", nil
	}
	_, user, err := h.services.Session.ValidateWithUser(r.Context(), cookie.Value)
	if errors.Is(err, domain.ErrSessionNotFound) || errors.Is(err, domain.ErrSessionExpired) || errors.Is(err, domain.ErrSessionRevoked) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if user == nil || user.IsBanned {
		return "", nil
	}
	return user.ID, nil
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

	// The public operation enqueues before account lookup. Queue failures are
	// account-independent infrastructure errors; the generic success sentinel
	// carries no account or delivery information.
	_, err := h.services.Verify.SendVerificationByEmail(r.Context(), body.Email)
	if !errors.Is(err, domain.ErrVerificationEmailSent) {
		h.writeError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"message": "If an account exists, a verification email will be sent"})
}
