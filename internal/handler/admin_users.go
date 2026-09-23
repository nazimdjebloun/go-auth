package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// parseListUsersInput reads the shared /admin/users query params. Offset,
// Limit, OrderBy and OrderDirection are only meaningful for the list;
// CountUsers ignores them.
func parseListUsersInput(r *http.Request, actorID string) (service.AdminListUsersInput, error) {
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

	var isBanned *bool
	if v := r.URL.Query().Get("isBanned"); v == "true" || v == "false" {
		b := v == "true"
		isBanned = &b
	}

	var isVerified *bool
	if v := r.URL.Query().Get("isVerified"); v == "true" || v == "false" {
		b := v == "true"
		isVerified = &b
	}

	var twoFactorEnabled *bool
	if v := r.URL.Query().Get("twoFactorEnabled"); v == "true" || v == "false" {
		b := v == "true"
		twoFactorEnabled = &b
	}

	var neverLoggedIn *bool
	if v := r.URL.Query().Get("neverLoggedIn"); v == "true" {
		b := true
		neverLoggedIn = &b
	}

	var lastLoginBefore *time.Time
	if v := r.URL.Query().Get("lastLoginBefore"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			lastLoginBefore = &t
		}
	}

	orderBy, orderDirection, err := parseUserSort(r.URL.Query())
	if err != nil {
		return service.AdminListUsersInput{}, err
	}

	return service.AdminListUsersInput{
		ActorID:          actorID,
		Offset:           offset,
		Limit:            limit,
		Email:            email,
		Role:             role,
		IsBanned:         isBanned,
		IsVerified:       isVerified,
		TwoFactorEnabled: twoFactorEnabled,
		NeverLoggedIn:    neverLoggedIn,
		LastLoginBefore:  lastLoginBefore,
		Search:           search,
		OrderBy:          orderBy,
		OrderDirection:   orderDirection,
	}, nil
}

// ListUsers returns users matching the request filters.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	input, err := parseListUsersInput(r, actor.ID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	result, err := h.services.Admin.ListUsers(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// CountUsers — GET /admin/users/count
func (h *Handler) CountUsers(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	input, err := parseListUsersInput(r, actor.ID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	n, err := h.services.Admin.CountUsers(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"count": n})
}

// BanUser bans a user.
func (h *Handler) BanUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	if err := h.services.Admin.BanUser(r.Context(), service.BanUserInput{UserID: userID, ActorID: actor.ID}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "User banned successfully"})
}

// UnbanUser unbans a user.
func (h *Handler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	if err := h.services.Admin.UnbanUser(r.Context(), service.UnbanUserInput{UserID: userID, ActorID: actor.ID}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "User unbanned successfully"})
}

// UpdateUserRole changes a user's role.
func (h *Handler) UpdateUserRole(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	var body struct {
		Role string `json:"role"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}
	if err := h.services.Admin.UpdateUserRole(r.Context(), service.UpdateUserRoleInput{UserID: userID, Role: body.Role, ActorID: actor.ID}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Role updated"})
}

// DeleteUser deletes a user.
func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	if err := h.services.Admin.DeleteUser(r.Context(), service.DeleteUserInput{UserID: userID, ActorID: actor.ID}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

// RevokeUserSessions revokes every session for a user.
func (h *Handler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	if err := h.services.Admin.RevokeUserSessions(r.Context(), service.RevokeUserSessionsInput{UserID: userID, ActorID: actor.ID}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Sessions revoked"})
}

// AdminCreateUser creates a user as an administrator.
func (h *Handler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
		Role     string `json:"role"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Admin.CreateUser(r.Context(), service.CreateUserInput{
		ActorID:  actor.ID,
		Email:    body.Email,
		Password: body.Password,
		Name:     body.Name,
		Role:     body.Role,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, result)
}

// AdminListUserSessions returns a user's sessions to an administrator.
func (h *Handler) AdminListUserSessions(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}

	sessions, total, aerr := h.services.Admin.ListUserSessions(r.Context(), service.AdminListUserSessionsInput{
		ActorID: actor.ID,
		UserID:  userID,
		Offset:  offset,
		Limit:   limit,
	})
	if aerr != nil {
		h.writeError(w, aerr)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions, "total": total})
}

// GetUserDetail returns one user's administrative details.
func (h *Handler) GetUserDetail(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")

	detail, aerr := h.services.Admin.GetUserDetail(r.Context(), service.GetUserDetailInput{UserID: userID, ActorID: actor.ID})
	if aerr != nil {
		h.writeError(w, aerr)
		return
	}
	h.writeJSON(w, http.StatusOK, detail)
}

// AdminRevokeUserSession revokes one user session as an administrator.
func (h *Handler) AdminRevokeUserSession(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	sessionID := r.PathValue("sessionId")

	if aerr := h.services.Admin.RevokeUserSession(r.Context(), service.RevokeUserSessionInput{UserID: userID, SessionID: sessionID, ActorID: actor.ID}); aerr != nil {
		h.writeError(w, aerr)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Session revoked"})
}
