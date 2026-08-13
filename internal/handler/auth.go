package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Auth.Register(r.Context(), service.RegisterInput{
		Email:     body.Email,
		Password:  body.Password,
		Name:      body.Name,
		IP:        extractIP(r.RemoteAddr),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeError(w, err)
		return
	}

	if result.RequiresVerification {
		writeJSON(w, http.StatusCreated, map[string]interface{}{
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

	middleware.SetSessionCookie(w, h.services.Session.Config(), result.SessionToken)
	middleware.SetRefreshCookie(w, h.services.Session.Config(), result.RefreshToken)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	result.SessionToken = ""
	result.RefreshToken = ""
	writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Auth.Login(r.Context(), service.LoginInput{
		Email:     body.Email,
		Password:  body.Password,
		IP:        extractIP(r.RemoteAddr),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeError(w, err)
		return
	}

	if result.RequiresVerification {
		writeJSON(w, http.StatusOK, map[string]interface{}{
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

	middleware.SetSessionCookie(w, h.services.Session.Config(), result.SessionToken)
	middleware.SetRefreshCookie(w, h.services.Session.Config(), result.RefreshToken)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	result.SessionToken = ""
	result.RefreshToken = ""
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) AdminLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Auth.AdminLogin(r.Context(), service.LoginInput{
		Email:     body.Email,
		Password:  body.Password,
		IP:        extractIP(r.RemoteAddr),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	if result.RequiresTwoFactor {
		h.writeTwoFactorChallenge(w, http.StatusOK, result.User, result.CodeSent, result.TwoFactorChallenge, result.TwoFactorExpiresAt, result.BindingToken())
		return
	}

	middleware.SetSessionCookie(w, h.services.Session.Config(), result.SessionToken)
	middleware.SetRefreshCookie(w, h.services.Session.Config(), result.RefreshToken)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	result.SessionToken = ""
	result.RefreshToken = ""
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	cfg := h.services.Session.Config()
	cookie, err := r.Cookie(cfg.CookieName)
	if err == nil && cookie.Value != "" {
		if err := h.services.Session.Revoke(r.Context(), cookie.Value); err != nil {
			h.log.Warn("logout revoke error", "err", err)
		}
	}
	middleware.ClearSessionCookie(w, h.services.Session.Config())
	middleware.ClearRefreshCookie(w, h.services.Session.Config())
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out"})
}

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	resp := struct {
		*domain.User
		HasPassword bool `json:"hasPassword"`
	}{user, user.HasPassword()}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) CheckAuth(w http.ResponseWriter, r *http.Request) {
	cfg := h.services.Session.Config()
	cookie, err := r.Cookie(cfg.CookieName)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"user": nil})
		return
	}

	user, _, aerr := h.services.Auth.ValidateSession(r.Context(), cookie.Value)
	if aerr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"user": nil})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (h *Handler) GetCSRFToken(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
func (h *Handler) ChangeName(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.services.Auth.ChangeName(r.Context(), user.ID, body.Name); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Name updated"})
}
