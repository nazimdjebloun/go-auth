package handler

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

type Services struct {
	Auth     *service.AuthService
	Password *service.PasswordService
	Session  *service.SessionService
	Verify   *service.VerificationService
	Invite   *service.InviteService
	Admin    *service.AdminService
}

type Handler struct {
	services Services
}

func New(s Services) *Handler {
	return &Handler{services: s}
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
		Email:    body.Email,
		Password: body.Password,
		Name:     body.Name,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	setSessionCookie(w, h.services.Session, result.SessionToken)
	result.SessionToken = ""
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
		IP:        r.RemoteAddr,
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeError(w, err)
		return
	}

	setSessionCookie(w, h.services.Session, result.SessionToken)
	result.SessionToken = ""
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("goauth_session")
	if err == nil && cookie.Value != "" {
		if err := h.services.Session.Revoke(r.Context(), cookie.Value); err != nil {
			log.Printf("logout revoke error: %v", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "goauth_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out"})
}

func (h *Handler) GetMe(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *Handler) CheckAuth(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("goauth_session")
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
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Password.ResetPassword(r.Context(), service.ResetPasswordInput{
		Email:       body.Email,
		Code:        body.Code,
		NewPassword: body.NewPassword,
	}); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	writeJSON(w, http.StatusOK, map[string]string{"message": "Password changed successfully"})
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
	clearSessionCookie(w, h.services.Session)
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

	if err := h.services.Verify.VerifyEmail(r.Context(), body.Code, body.Email); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, domain.NewError("forbidden", "Not authenticated", 403))
		return
	}

	if err := h.services.Verify.ResendVerification(r.Context(), user.ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Session handlers ---

func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	currentSession := middleware.GetSessionFromContext(r.Context())

	sessions, err := h.services.Session.List(r.Context(), user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
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

	sessions, err := h.services.Session.List(r.Context(), user.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}

	found := false
	for _, s := range sessions {
		if s.ID == sessionID {
			found = true
			break
		}
	}
	if !found {
		writeError(w, domain.NewError("session_not_found", "Session not found", http.StatusNotFound))
		return
	}

	if err := h.services.Session.RevokeByID(r.Context(), sessionID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Session revoked"})
}

func (h *Handler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	currentSession := middleware.GetSessionFromContext(r.Context())

	if currentSession != nil {
		if err := h.services.Session.RevokeAllExcept(r.Context(), user.ID, currentSession.ID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
	} else {
		if err := h.services.Session.RevokeAll(r.Context(), user.ID); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error"})
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Sessions revoked"})
}

// --- Invite handlers ---

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
	})
	if err != nil {
		writeError(w, err)
		return
	}

	setSessionCookie(w, h.services.Session, result.SessionToken)
	result.SessionToken = ""
	writeJSON(w, http.StatusCreated, result)
}

// --- Admin handlers ---

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 100 {
		limit = 20
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
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if err := h.services.Admin.UnbanUser(r.Context(), userID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	w.WriteHeader(http.StatusNoContent)
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

	sessions, aerr := h.services.Admin.ListUserSessions(r.Context(), service.AdminListUserSessionsInput{
		UserID: userID,
		Offset: offset,
		Limit:  limit,
	})
	if aerr != nil {
		writeError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
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
	if limit == 0 || limit > 100 {
		limit = 20
	}

	invites, total, err := h.services.Invite.ListInvites(r.Context(), offset, limit)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": invites, "total": total})
}

func (h *Handler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	inviteID := r.PathValue("id")
	if err := h.services.Invite.RevokeInvite(r.Context(), inviteID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ResendInvite(w http.ResponseWriter, r *http.Request) {
	inviteID := r.PathValue("id")
	if err := h.services.Invite.ResendInviteEmail(r.Context(), inviteID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Helpers ---

const maxBodySize = 1 << 16 // 64 KB

func setSessionCookie(w http.ResponseWriter, svc *service.SessionService, token string) {
	cfg := svc.Config()
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.SecureCookie,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   int(cfg.Duration.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter, svc *service.SessionService) {
	cfg := svc.Config()
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   cfg.SecureCookie,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   -1,
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
		log.Printf("Failed to encode JSON: %v", err)
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
