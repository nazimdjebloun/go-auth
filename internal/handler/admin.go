package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
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

	orderBy := r.URL.Query().Get("orderBy")
	if orderBy != "created_at" && orderBy != "updated_at" {
		orderBy = "created_at"
	}

	orderDirection := r.URL.Query().Get("orderDirection")
	if orderDirection != "asc" && orderDirection != "desc" {
		orderDirection = "desc"
	}

	result, err := h.services.Admin.ListUsers(r.Context(), service.AdminListUsersInput{
		ActorID:          actor.ID,
		Offset:           offset,
		Limit:            limit,
		Email:            email,
		Role:             role,
		TwoFactorEnabled: twoFactorEnabled,
		NeverLoggedIn:    neverLoggedIn,
		LastLoginBefore:  lastLoginBefore,
		Search:           search,
		OrderBy:          orderBy,
		OrderDirection:   orderDirection,
	})
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) BanUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	if err := h.services.Admin.BanUser(r.Context(), service.BanUserInput{UserID: userID, ActorID: actor.ID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "User banned successfully"})
}

func (h *Handler) UnbanUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	if err := h.services.Admin.UnbanUser(r.Context(), service.UnbanUserInput{UserID: userID, ActorID: actor.ID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "User unbanned successfully"})
}

func (h *Handler) UpdateUserRole(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	var body struct {
		Role string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if err := h.services.Admin.UpdateUserRole(r.Context(), service.UpdateUserRoleInput{UserID: userID, Role: body.Role, ActorID: actor.ID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Role updated"})
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	if err := h.services.Admin.DeleteUser(r.Context(), service.DeleteUserInput{UserID: userID, ActorID: actor.ID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "User deleted successfully"})
}

func (h *Handler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	if err := h.services.Admin.RevokeUserSessions(r.Context(), service.RevokeUserSessionsInput{UserID: userID, ActorID: actor.ID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Sessions revoked"})
}

func (h *Handler) AdminCreateUser(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
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
		ActorID:  actor.ID,
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
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
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
		writeError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions, "total": total})
}

func (h *Handler) GetUserDetail(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")

	detail, aerr := h.services.Admin.GetUserDetail(r.Context(), service.GetUserDetailInput{UserID: userID, ActorID: actor.ID})
	if aerr != nil {
		writeError(w, aerr)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (h *Handler) AdminRevokeUserSession(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	sessionID := r.PathValue("sessionId")

	if aerr := h.services.Admin.RevokeUserSession(r.Context(), service.RevokeUserSessionInput{UserID: userID, SessionID: sessionID, ActorID: actor.ID}); aerr != nil {
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

// GetAdminStats returns platform-wide counts for an admin dashboard —
// total/verified/banned/two-factor/never-logged-in users and active
// sessions. No params.
func (h *Handler) GetAdminStats(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	stats, err := h.services.Admin.GetStats(r.Context(), actor.ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// parseStatsRange reads and validates the required from/to RFC3339 query
// params shared by GetRegistrationTrend and GetLoginActivity.
func parseStatsRange(w http.ResponseWriter, r *http.Request) (from, to time.Time, ok bool) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_input", "message": "from and to are required"})
		return time.Time{}, time.Time{}, false
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_input", "message": "from must be RFC3339"})
		return time.Time{}, time.Time{}, false
	}
	to, err = time.Parse(time.RFC3339, toStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_input", "message": "to must be RFC3339"})
		return time.Time{}, time.Time{}, false
	}
	return from, to, true
}

// GetRegistrationTrend returns registrations per day over [from, to] (both
// required, RFC3339) — the data behind a registrations-over-time chart.
func (h *Handler) GetRegistrationTrend(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	from, to, ok := parseStatsRange(w, r)
	if !ok {
		return
	}
	counts, err := h.services.Admin.GetRegistrationTrend(r.Context(), service.StatsRangeInput{
		ActorID: actor.ID, From: from, To: to,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"registrations": counts})
}

// GetLoginActivity returns successful-login counts per day over [from, to]
// (both required, RFC3339) — the data behind a GitHub-commit-style login
// heatmap. Global (every user) by default; pass userId for one user's.
func (h *Handler) GetLoginActivity(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	from, to, ok := parseStatsRange(w, r)
	if !ok {
		return
	}
	var userID *string
	if v := r.URL.Query().Get("userId"); v != "" {
		userID = &v
	}
	counts, err := h.services.Admin.GetLoginActivity(r.Context(), service.LoginActivityInput{
		ActorID: actor.ID, UserID: userID, From: from, To: to,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"logins": counts})
}
