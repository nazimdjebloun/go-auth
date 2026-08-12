package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

type Services struct {
	Auth      *service.AuthService
	Password  *service.PasswordService
	Session   *service.SessionService
	Verify    *service.VerificationService
	Invite    *service.InviteService
	Admin     *service.AdminService
	OAuth     *service.OAuthService
	Org       *service.OrgService
	OrgInvite *service.OrgInviteService
	TwoFactor *service.TwoFactorService
	AuditLog  port.AuditLogRepository
}

type Handler struct {
	services     Services
	log          *slog.Logger
	csrfTokenCfg *middleware.CSRFTokenConfig
}

func New(s Services) *Handler {
	return &Handler{services: s, log: slog.Default()}
}

func NewWithLogger(s Services, logger *slog.Logger, csrfTokenCfg *middleware.CSRFTokenConfig) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{services: s, log: logger, csrfTokenCfg: csrfTokenCfg}
}

// --- Auth handlers ---

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

// --- Password handlers ---

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

// --- Verification handlers ---

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	user, err := h.services.Verify.VerifyEmail(r.Context(), body.Code)
	if err != nil {
		writeError(w, err)
		return
	}

	session, rawToken, refreshToken, sessionErr := h.services.Session.Create(r.Context(), user.ID, extractIP(r.RemoteAddr), r.UserAgent())
	if sessionErr != nil {
		h.log.Error("failed to create session after verification", "err", sessionErr, "user_id", user.ID)
		writeError(w, domain.NewError("internal_error", "Internal server error", 500))
		return
	}

	middleware.SetSessionCookie(w, h.services.Session.Config(), rawToken)
	middleware.SetRefreshCookie(w, h.services.Session.Config(), refreshToken)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user":    user,
		"session": session,
	})
}

func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, domain.NewError("forbidden", "Not authenticated", 403))
		return
	}

	result, err := h.services.Verify.ResendVerification(r.Context(), user.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	// codeSent distinguishes a fresh send from a still-valid code left in
	// place, the same way the 2FA challenge response does — without it a
	// deliberate skip and a dead mailer are the same 200 to the client.
	message := "A verification code was already sent, check your email"
	if result.Sent {
		message = "Verification email sent"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"codeSent":  result.Sent,
		"expiresAt": result.ExpiresAt,
		"message":   message,
	})
}

func (h *Handler) ResendVerificationPublic(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	// Both return values are dropped deliberately: this endpoint is
	// unauthenticated, so the error distinguishes "no such account" and Sent
	// distinguishes "already had a live code" — each of which would turn the
	// flat reply below into an account-existence oracle. The authenticated
	// ResendVerification above is where codeSent is safe to expose.
	_, _ = h.services.Verify.SendVerificationByEmail(r.Context(), body.Email)

	writeJSON(w, http.StatusOK, map[string]string{"message": "If an account exists, a verification email has been sent"})
}

// --- Session handlers ---

// POST /auth/refresh
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	cfg := h.services.Session.Config()
	cookie, err := r.Cookie(cfg.RefreshCookieName)
	if err != nil || cookie.Value == "" {
		writeError(w, domain.NewError("invalid_refresh", "No refresh token provided", 401))
		return
	}

	session, rawToken, refreshToken, err := h.services.Session.RefreshSession(r.Context(), cookie.Value)
	if err != nil {
		middleware.ClearSessionCookie(w, h.services.Session.Config())
		middleware.ClearRefreshCookie(w, h.services.Session.Config())
		if authErr, ok := err.(*domain.AuthError); ok {
			writeError(w, authErr)
		} else {
			h.log.Error("refresh token error", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
		}
		return
	}

	middleware.SetSessionCookie(w, h.services.Session.Config(), rawToken)
	middleware.SetRefreshCookie(w, h.services.Session.Config(), refreshToken)
	writeJSON(w, http.StatusOK, map[string]any{
		"session": map[string]any{
			"id":          session.ID,
			"user_id":     session.UserID,
			"expires_at":  session.ExpiresAt,
			"last_active": session.LastActiveAt,
		},
	})
}

func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	currentSession := middleware.GetSessionFromContext(r.Context())

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}

	sessions, total, err := h.services.Session.List(r.Context(), user.ID, offset, limit)
	if err != nil {
		h.log.Error("failed to list sessions", "err", err, "user_id", user.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
		return
	}
	currentSessionID := ""
	if currentSession != nil {
		currentSessionID = currentSession.ID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions":           sessions,
		"total":              total,
		"limit":              limit,
		"offset":             offset,
		"current_session_id": currentSessionID,
	})
}

func (h *Handler) GetAllSessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	currentSession := middleware.GetSessionFromContext(r.Context())

	sessions, err := h.services.Session.ListAll(r.Context(), user.ID)
	if err != nil {
		h.log.Error("failed to list all sessions", "err", err, "user_id", user.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
		return
	}
	currentSessionID := ""
	if currentSession != nil {
		currentSessionID = currentSession.ID
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sessions":           sessions,
		"current_session_id": currentSessionID,
	})
}

func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	sessionID := r.PathValue("id")

	revoked, err := h.services.Session.RevokeByIDForUser(r.Context(), sessionID, user.ID)
	if err != nil {
		h.log.Error("failed to revoke session", "err", err, "user_id", user.ID, "session_id", sessionID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
		return
	}
	if !revoked {
		writeError(w, domain.NewError("session_not_found", "Session not found", http.StatusNotFound))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Session revoked"})
}

func (h *Handler) RevokeManySessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())

	var body struct {
		SessionIDs []string `json:"session_ids"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if len(body.SessionIDs) == 0 {
		writeError(w, domain.NewError("invalid_input", "session_ids must not be empty", http.StatusBadRequest))
		return
	}
	if len(body.SessionIDs) > 100 {
		writeError(w, domain.NewError("invalid_input", "cannot revoke more than 100 sessions at once", http.StatusBadRequest))
		return
	}

	revoked, err := h.services.Session.RevokeManyForUser(r.Context(), body.SessionIDs, user.ID)
	if err != nil {
		h.log.Error("failed to revoke sessions", "err", err, "user_id", user.ID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": revoked})
}

func (h *Handler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	currentSession := middleware.GetSessionFromContext(r.Context())

	if currentSession != nil {
		if err := h.services.Session.RevokeAllExcept(r.Context(), user.ID, currentSession.ID); err != nil {
			h.log.Error("failed to revoke sessions", "err", err, "user_id", user.ID)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
			return
		}
	} else {
		if err := h.services.Session.RevokeAll(r.Context(), user.ID); err != nil {
			h.log.Error("failed to revoke all sessions", "err", err, "user_id", user.ID)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Sessions revoked"})
}

// --- Invite handlers ---

func (h *Handler) GetInviteInfo(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, domain.NewError("missing_token", "Token is required", 400))
		return
	}

	invite, err := h.services.Invite.GetInviteByToken(r.Context(), token)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"email": invite.Email})
}

func (h *Handler) InviteRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code            string `json:"code"`
		Name            string `json:"name"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Invite.CompleteInviteRegistration(r.Context(), service.CompleteInviteInput{
		Code:            body.Code,
		Name:            body.Name,
		Password:        body.Password,
		ConfirmPassword: body.ConfirmPassword,
		IP:              extractIP(r.RemoteAddr),
		UserAgent:       r.UserAgent(),
	})
	if err != nil {
		writeError(w, err)
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

// --- Two-factor handlers ---

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

	user, session, rawToken, refreshToken, err := h.services.TwoFactor.Verify(
		r.Context(), body.ChallengeID, h.twoFactorBindingCookieValue(r), body.Code,
		extractIP(r.RemoteAddr), r.UserAgent(),
	)
	if err != nil {
		writeError(w, err)
		return
	}

	middleware.SetSessionCookie(w, h.services.Session.Config(), rawToken)
	middleware.SetRefreshCookie(w, h.services.Session.Config(), refreshToken)
	h.clearTwoFactorBindingCookie(w)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	writeJSON(w, http.StatusOK, map[string]any{"user": user, "session": session})
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

// --- Admin handlers ---

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}

	var email *string
	if e := r.URL.Query().Get("email"); e != "" {
		email = &e
	}

	var search *string
	if s := r.URL.Query().Get("search"); s != "" {
		search = &s
	}

	var role *domain.Role
	if rl := r.URL.Query().Get("role"); rl == "admin" || rl == "user" {
		r := domain.Role(rl)
		role = &r
	}

	orderBy := r.URL.Query().Get("orderBy")
	if orderBy != "created_at" && orderBy != "updated_at" {
		orderBy = "created_at"
	}

	orderDirection := r.URL.Query().Get("orderDirection")
	if orderDirection != "asc" && orderDirection != "desc" {
		orderDirection = "desc"
	}

	result, err := h.services.Admin.ListUsers(r.Context(), service.AdminListUsersInput{
		Offset:         offset,
		Limit:          limit,
		Email:          email,
		Role:           role,
		Search:         search,
		OrderBy:        orderBy,
		OrderDirection: orderDirection,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) BanUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if err := h.services.Admin.BanUser(r.Context(), userID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "User banned successfully"})
}

func (h *Handler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if err := h.services.Admin.UnbanUser(r.Context(), userID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "User unbanned successfully"})
}

func (h *Handler) UpdateUserRole(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	var body struct {
		Role string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.services.Admin.UpdateUserRole(r.Context(), userID, body.Role); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Role updated"})
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if err := h.services.Admin.DeleteUser(r.Context(), userID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

func (h *Handler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if err := h.services.Admin.RevokeUserSessions(r.Context(), userID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Sessions revoked"})
}

func (h *Handler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
		Role     string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Admin.CreateUser(r.Context(), service.CreateUserInput{
		Email:    body.Email,
		Password: body.Password,
		Name:     body.Name,
		Role:     body.Role,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) AdminListUserSessions(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}

	sessions, total, aerr := h.services.Admin.ListUserSessions(r.Context(), service.AdminListUserSessionsInput{
		UserID: userID,
		Offset: offset,
		Limit:  limit,
	})
	if aerr != nil {
		writeError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions, "total": total})
}

func (h *Handler) GetUserDetail(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	detail, aerr := h.services.Admin.GetUserDetail(r.Context(), userID)
	if aerr != nil {
		writeError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *Handler) AdminRevokeUserSession(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	sessionID := r.PathValue("sessionId")

	if aerr := h.services.Admin.RevokeUserSession(r.Context(), userID, sessionID); aerr != nil {
		writeError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Session revoked"})
}

func (h *Handler) AdminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	h.listAuditLogs(w, r, nil)
}

func (h *Handler) AdminListUserAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	h.listAuditLogs(w, r, &userID)
}

func (h *Handler) listAuditLogs(w http.ResponseWriter, r *http.Request, userID *string) {
	if h.services.AuditLog == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "audit_not_configured", "message": "Audit logging is not enabled"})
		return
	}

	filter := port.AuditLogFilter{
		Offset: 0,
		Limit:  50,
	}

	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Offset = n
		}
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			filter.Limit = n
		}
	}
	if filter.Limit <= 0 {
		filter.Limit = 50
	} else if filter.Limit > 200 {
		filter.Limit = 200
	}

	if v := r.URL.Query().Get("event_type"); v != "" {
		filter.Type = &v
	}
	if v := r.URL.Query().Get("actor_id"); v != "" {
		filter.ActorID = &v
	}
	if v := r.URL.Query().Get("target_user_id"); v != "" {
		filter.TargetUserID = &v
	}
	if v := r.URL.Query().Get("session_id"); v != "" {
		filter.SessionID = &v
	}
	if v := r.URL.Query().Get("org_id"); v != "" {
		filter.OrgID = &v
	}
	if v := r.URL.Query().Get("search"); v != "" {
		filter.Search = &v
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.FromDate = &t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			filter.ToDate = &t
		}
	}
	if v := r.URL.Query().Get("success"); v == "true" {
		b := true
		filter.Success = &b
	} else if v := r.URL.Query().Get("success"); v == "false" {
		b := false
		filter.Success = &b
	}

	if userID != nil {
		filter.TargetUserID = userID
	}

	events, total, err := h.services.AuditLog.List(r.Context(), filter)
	if err != nil {
		h.log.ErrorContext(r.Context(), "failed to list audit logs", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Failed to list audit logs"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"total":  total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())

	var body struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Invite.CreateInvite(r.Context(), service.CreateInviteInput{
		Email:   body.Email,
		AdminID: user.ID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) ListInvites(w http.ResponseWriter, r *http.Request) {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}

	invites, total, err := h.services.Invite.ListInvites(r.Context(), service.ListInvitesInput{
		Offset: offset,
		Limit:  limit,
		Search: r.URL.Query().Get("search"),
		Status: r.URL.Query().Get("status"),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": invites, "total": total})
}

func (h *Handler) HardDeleteInvite(w http.ResponseWriter, r *http.Request) {
	inviteID := r.PathValue("id")
	if err := h.services.Invite.HardDeleteInvite(r.Context(), inviteID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite deleted"})
}

func (h *Handler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	inviteID := r.PathValue("id")
	if err := h.services.Invite.RevokeInvite(r.Context(), inviteID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite revoked"})
}

func (h *Handler) ResendInvite(w http.ResponseWriter, r *http.Request) {
	inviteID := r.PathValue("id")
	if err := h.services.Invite.ResendInviteEmail(r.Context(), inviteID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite resent"})
}

// --- Helpers ---

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

func writeError(w http.ResponseWriter, err *domain.AuthError) {
	status := err.HTTPStatus
	if status == 0 {
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, map[string]string{
		"error":   err.Code,
		"message": err.Message,
	})
}

// Deprecated: use middleware.GetUserFromContext instead.
func GetUserID(ctx context.Context) string {
	user := middleware.GetUserFromContext(ctx)
	if user == nil {
		return ""
	}
	return user.ID
}

func extractIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}
