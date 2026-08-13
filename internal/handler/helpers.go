package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/httperr"
)

const maxBodySize = 1 << 16 // 64 KB

// setTwoFactorBindingCookie ties a 2FA challenge to this browser. It travels
// exactly as far as the session cookie — same Domain/Path/Secure/SameSite —
// so there's only one cookie-reach story to maintain, not two. No-op when
// binding is disabled or the token is empty (Challenge/Resend return an
// empty BindingToken in that case).
func (h *Handler) setTwoFactorBindingCookie(w http.ResponseWriter, token string) {
	if h.services.TwoFactor == nil || h.services.TwoFactor.BindingDisabled() || token == "" {
		return
	}
	cfg := h.services.Session.Config()
	http.SetCookie(w, &http.Cookie{
		Name:     h.services.TwoFactor.CookieName(),
		Value:    token,
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   int(h.services.TwoFactor.CookieTTL().Seconds()),
	})
}

func (h *Handler) clearTwoFactorBindingCookie(w http.ResponseWriter) {
	if h.services.TwoFactor == nil {
		return
	}
	cfg := h.services.Session.Config()
	http.SetCookie(w, &http.Cookie{
		Name:     h.services.TwoFactor.CookieName(),
		Value:    "",
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   -1,
	})
}

func (h *Handler) twoFactorBindingCookieValue(r *http.Request) string {
	if h.services.TwoFactor == nil {
		return ""
	}
	c, err := r.Cookie(h.services.TwoFactor.CookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

// writeTwoFactorChallenge is the shared gated response for
// Login/Register/AdminLogin/InviteRegister: a second factor is still owed, so
// no session/refresh cookie is set and CSRF is not rotated. The binding
// cookie is the one exception — it is not a session credential on its own,
// see TwoFactorService.
func (h *Handler) writeTwoFactorChallenge(w http.ResponseWriter, status int, user *domain.User, codeSent bool, challengeID string, expiresAt time.Time, bindingToken string) {
	h.setTwoFactorBindingCookie(w, bindingToken)
	message := "A two-factor code was already sent, check your email"
	if codeSent {
		message = "Two-factor code sent to your email"
	}
	writeJSON(w, status, map[string]any{
		"user":              user,
		"requiresTwoFactor": true,
		"codeSent":          codeSent,
		"challengeId":       challengeID,
		"expiresAt":         expiresAt,
		"message":           message,
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "message": "Invalid request body"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "err", err, "status", status)
	}
}

// writeError writes err as the HTTP response. When err is (or wraps) a
// *domain.AuthError, its Code/Message drive the response, and
// httperr.StatusFor(authErr.Code) picks the status — every service method's
// error return is expected to be one. Anything else reaching here is a bug
// in the service layer's error contract, not a normal failure mode: it's
// logged and answered as a generic 500 rather than leaking an unexpected
// error's text to the client.
func writeError(w http.ResponseWriter, err error) {
	var authErr *domain.AuthError
	if errors.As(err, &authErr) {
		writeJSON(w, httperr.StatusFor(authErr.Code), map[string]string{
			"error":   authErr.Code,
			"message": authErr.Message,
		})
		return
	}
	slog.Error("writeError: non-AuthError reached the HTTP layer", "err", err)
	writeJSON(w, http.StatusInternalServerError, map[string]string{
		"error":   "internal_error",
		"message": "Internal server error",
	})
}

func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
