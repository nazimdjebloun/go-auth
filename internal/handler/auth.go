package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Auth.Register(r.Context(), service.RegisterInput{
		Email:     body.Email,
		Password:  body.Password,
		Name:      body.Name,
		IP:        h.ip(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}

	if result.RequiresVerification {
		h.writeJSON(w, http.StatusCreated, map[string]interface{}{
			"user":                 result.User,
			"requiresVerification": true,
			"message":              "Verification email sent. Please verify your email to continue.",
		})
		return
	}
	if result.RequiresTwoFactor {
		h.writeTwoFactorChallenge(w, http.StatusCreated, result.User, result.CodeSent, result.TwoFactorChallenge, result.TwoFactorExpiresAt, result.BindingToken())
		return
	}

	middleware.SetSessionCookie(w, h.cookies, result.SessionToken)
	middleware.SetRefreshCookie(w, h.cookies, result.RefreshToken)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	result.SessionToken = ""
	result.RefreshToken = ""
	h.writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Auth.Login(r.Context(), service.LoginInput{
		Email:     body.Email,
		Password:  body.Password,
		IP:        h.ip(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}

	if result.RequiresVerification {
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"user":                 result.User,
			"requiresVerification": true,
			"message":              "Please verify your email to continue.",
		})
		return
	}
	if result.RequiresTwoFactor {
		h.writeTwoFactorChallenge(w, http.StatusOK, result.User, result.CodeSent, result.TwoFactorChallenge, result.TwoFactorExpiresAt, result.BindingToken())
		return
	}

	middleware.SetSessionCookie(w, h.cookies, result.SessionToken)
	middleware.SetRefreshCookie(w, h.cookies, result.RefreshToken)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	result.SessionToken = ""
	result.RefreshToken = ""
	h.writeJSON(w, http.StatusOK, result)
}

func (h *Handler) AdminLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Auth.AdminLogin(r.Context(), service.LoginInput{
		Email:     body.Email,
		Password:  body.Password,
		IP:        h.ip(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	if result.RequiresTwoFactor {
		h.writeTwoFactorChallenge(w, http.StatusOK, result.User, result.CodeSent, result.TwoFactorChallenge, result.TwoFactorExpiresAt, result.BindingToken())
		return
	}

	middleware.SetSessionCookie(w, h.cookies, result.SessionToken)
	middleware.SetRefreshCookie(w, h.cookies, result.RefreshToken)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	result.SessionToken = ""
	result.RefreshToken = ""
	h.writeJSON(w, http.StatusOK, result)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	session := middleware.GetSessionFromContext(r.Context())
	if session == nil {
		h.writeError(w, domain.ErrSessionExpired)
		return
	}
	if err := h.services.Auth.Logout(r.Context(), session.ID); err != nil {
		h.writeError(w, err)
		return
	}

	middleware.ClearSessionCookie(w, h.cookies)
	middleware.ClearRefreshCookie(w, h.cookies)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out"})
}

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	// Session travels alongside the user because the active org lives on it
	// and is otherwise unreadable by a client: PUT/DELETE /auth/orgs/active
	// only answer with a bare {"message"}. Every token hash on domain.Session
	// is `json:"-"`, so nothing secret leaves with it, and it is the caller's
	// own session either way.
	resp := struct {
		*domain.User
		HasPassword bool            `json:"hasPassword"`
		Session     *domain.Session `json:"session,omitempty"`
	}{user, user.HasPassword(), middleware.GetSessionFromContext(r.Context())}
	h.writeJSON(w, http.StatusOK, resp)
}

// GetCSRFToken primes the double-submit cookie. The CSRF middleware wrapping
// this route is what actually issues it; this handler only decides whether the
// value is also echoed in the body.
//
// It answers 204 with no body by default. A client on the same origin, or on a
// sibling subdomain with CookieDomain set, reads the token from document.cookie
// and needs nothing here.
//
// With CSRFTokenConfig.ExposeCSRFTokenInBody it answers 200 {"token": "..."} — the
// opt-in for a frontend on a different registrable domain, which cannot read
// the cookie however it is scoped. no-store because a 200 with a body is
// cacheable where a 204 was not, and a shared cache handing one visitor's
// token to the next would hand over a working one.
func (h *Handler) GetCSRFToken(w http.ResponseWriter, r *http.Request) {
	if h.csrfTokenCfg == nil || !h.csrfTokenCfg.ExposeCSRFTokenInBody {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	token := middleware.CSRFTokenFromContext(r.Context())
	if token == "" {
		// The middleware issues on every safe method, so this means it is not
		// in front of this route at all. Nothing to hand back.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusOK, map[string]string{"token": token})
}
func (h *Handler) ChangeName(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}
	if err := h.services.Auth.ChangeName(r.Context(), user.ID, body.Name); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Name updated"})
}
