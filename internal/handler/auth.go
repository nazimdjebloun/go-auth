package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// Register creates a user account.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if sessioncontext.Current(r.Context()) == sessioncontext.Admin {
		h.writeError(w, domain.ErrInvalidSessionContext)
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Auth.Register(r.Context(), api.RegisterInput{
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
		h.writeTwoFactorChallenge(w, r, http.StatusCreated, result.User, result.CodeSent, result.TwoFactorChallenge, result.TwoFactorExpiresAt, result.BindingToken())
		return
	}

	if !h.issueSessionCookies(w, r, result.Session, result.SessionToken, result.RefreshToken) {
		return
	}
	result.SessionToken = ""
	result.RefreshToken = ""
	h.writeJSON(w, http.StatusCreated, result)
}

// Login authenticates a user.
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Auth.Login(r.Context(), api.LoginInput{
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
		h.writeTwoFactorChallenge(w, r, http.StatusOK, result.User, result.CodeSent, result.TwoFactorChallenge, result.TwoFactorExpiresAt, result.BindingToken())
		return
	}

	if !h.issueSessionCookies(w, r, result.Session, result.SessionToken, result.RefreshToken) {
		return
	}
	result.SessionToken = ""
	result.RefreshToken = ""
	h.writeJSON(w, http.StatusOK, result)
}

// AdminLogin authenticates an administrator.
func (h *Handler) AdminLogin(w http.ResponseWriter, r *http.Request) {
	r = r.WithContext(sessioncontext.With(r.Context(), sessioncontext.Admin))
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Auth.AdminLogin(r.Context(), api.LoginInput{
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
		h.writeTwoFactorChallenge(w, r, http.StatusOK, result.User, result.CodeSent, result.TwoFactorChallenge, result.TwoFactorExpiresAt, result.BindingToken())
		return
	}

	if !h.issueSessionCookies(w, r, result.Session, result.SessionToken, result.RefreshToken) {
		return
	}
	result.SessionToken = ""
	result.RefreshToken = ""
	h.writeJSON(w, http.StatusOK, result)
}

// Logout ends the current session.
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

	if !h.clearSessionCookies(w, r) {
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out"})
}

// GetMe returns the authenticated user.
func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	if h.services.RequireEmailVerification && !user.IsVerified {
		h.writeJSON(w, http.StatusOK, map[string]any{"id": user.ID, "email": user.Email, "isVerified": false, "requiresVerification": true})
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

// GetCSRFToken returns the mandatory double-submit token. The cookie remains
// HttpOnly; same-origin and allowed cross-origin clients use this JSON response.
func (h *Handler) GetCSRFToken(w http.ResponseWriter, r *http.Request) {
	token := middleware.CSRFTokenFromContext(r.Context())
	if token == "" {
		h.writeError(w, domain.ErrInternal)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// ChangeName updates the authenticated user's name.
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
	if err := h.services.Auth.ChangeName(r.Context(), api.ChangeNameInput{
		UserID: user.ID,
		Name:   body.Name,
	}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Name updated"})
}
