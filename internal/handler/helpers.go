package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/httperr"
)

const maxBodySize = 1 << 16 // 64 KB

type bindingCookieParams struct {
	name     string
	value    string
	domain   string
	path     string
	secure   bool
	sameSite http.SameSite
	maxAge   int
}

func newBindingCookie(params bindingCookieParams) *http.Cookie {
	cookie := &http.Cookie{
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
	cookie.Name = params.name
	cookie.Value = params.value
	cookie.Domain = params.domain
	cookie.Path = params.path
	cookie.HttpOnly = true
	cookie.Secure = params.secure
	cookie.SameSite = params.sameSite
	cookie.MaxAge = params.maxAge
	return cookie
}

// setTwoFactorBindingCookie ties a 2FA challenge to this browser. It travels
// exactly as far as the session cookie — same Domain/Path/Secure/SameSite —
// so there's only one cookie-reach story to maintain, not two. No-op when
// binding is disabled or the token is empty (Challenge/Resend return an
// empty BindingToken in that case).
func (h *Handler) setTwoFactorBindingCookie(w http.ResponseWriter, token string) {
	if h.services.TwoFactor == nil || h.services.TwoFactor.BindingDisabled() || token == "" {
		return
	}
	http.SetCookie(w, newBindingCookie(bindingCookieParams{
		name:     h.services.TwoFactor.CookieName(),
		value:    token,
		domain:   h.cookies.Domain,
		path:     h.cookies.Path,
		secure:   h.cookies.Secure,
		sameSite: http.SameSite(h.cookies.SameSite),
		maxAge:   int(h.services.TwoFactor.CookieTTL().Seconds()),
	}))
}

func (h *Handler) clearTwoFactorBindingCookie(w http.ResponseWriter) {
	if h.services.TwoFactor == nil {
		return
	}
	http.SetCookie(w, newBindingCookie(bindingCookieParams{
		name:     h.services.TwoFactor.CookieName(),
		domain:   h.cookies.Domain,
		path:     h.cookies.Path,
		secure:   h.cookies.Secure,
		sameSite: http.SameSite(h.cookies.SameSite),
		maxAge:   -1,
	}))
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
	h.writeJSON(w, status, map[string]any{
		"user":              user,
		"requiresTwoFactor": true,
		"codeSent":          codeSent,
		"challengeId":       challengeID,
		"expiresAt":         expiresAt,
		"message":           message,
	})
}

func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json", "message": "Invalid request body"})
		return false
	}
	return true
}

// writeJSONTo is the one place a handler response is serialized. It takes
// the logger explicitly because the encode failure it reports is a server
// fault the consumer needs in their own log, not slog's default sink —
// callers reach it through the writeJSON method on their handler type.
func writeJSONTo(log *slog.Logger, w http.ResponseWriter, status int, v any) {
	if log == nil {
		log = slog.Default()
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error("failed to encode JSON response", "err", err, "status", status)
	}
}

// writeError writes err as the HTTP response. When err is (or wraps) a
// *domain.AuthError, its Code/Message drive the response, and
// httperr.StatusFor(authErr.Code) picks the status — every service method's
// error return is expected to be one. Anything else reaching here is a bug
// in the service layer's error contract, not a normal failure mode: it's
// logged and answered as a generic 500 rather than leaking an unexpected
// error's text to the client.
func writeErrorTo(log *slog.Logger, w http.ResponseWriter, err error) {
	var authErr *domain.AuthError
	if errors.As(err, &authErr) {
		writeJSONTo(log, w, httperr.StatusFor(authErr.Code), map[string]string{
			"error":   authErr.Code,
			"message": authErr.Message,
		})
		return
	}
	if log == nil {
		log = slog.Default()
	}
	log.Error("writeError: non-AuthError reached the HTTP layer", "err", err)
	writeJSONTo(log, w, http.StatusInternalServerError, map[string]string{
		"error":   "internal_error",
		"message": "Internal server error",
	})
}

// parseOrgRole reads the optional ?role= filter shared by every org listing.
// An absent or empty param means "no filter". An unrecognized value is
// rejected rather than dropped: a filter that silently widens returns rows the
// caller explicitly asked to exclude, and a console rendering them under the
// label it filtered by shows a confidently wrong answer. Ordering params fall
// back to a default instead, because a wrong sort is cosmetic and visible on
// screen; a wrong filter is neither. This also matches what the service layer
// already does with a role on a mutation input — OrgRole.IsValid there is a
// 400, not a shrug.
//
// Reports false once it has written the response, so callers return early.
func (h *Handler) parseOrgRole(w http.ResponseWriter, r *http.Request) (*domain.OrgRole, bool) {
	v := r.URL.Query().Get("role")
	if v == "" {
		return nil, true
	}
	role := domain.OrgRole(v)
	if !role.IsValid() {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":   "invalid_input",
			"message": "role must be owner, admin, or member",
		})
		return nil, false
	}
	return &role, true
}

// writeJSON and writeError are methods rather than package functions so the
// server-fault they report reaches the logger the consumer configured with
// WithLogger. Both handler types carry one.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	writeJSONTo(h.log, w, status, v)
}

func (h *Handler) writeError(w http.ResponseWriter, err error) {
	writeErrorTo(h.log, w, err)
}

func (h *OAuthHandlers) writeJSON(w http.ResponseWriter, status int, v any) {
	writeJSONTo(h.log, w, status, v)
}

func (h *OAuthHandlers) writeError(w http.ResponseWriter, err error) {
	writeErrorTo(h.log, w, err)
}
