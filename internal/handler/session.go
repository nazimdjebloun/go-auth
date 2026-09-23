package handler

import (
	"net/http"
	"strconv"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// RefreshToken rotates the current session tokens.
// POST /auth/refresh
func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(h.cookies.RefreshName)
	if err != nil || cookie.Value == "" {
		h.writeError(w, domain.NewError("invalid_refresh", "No refresh token provided"))
		return
	}

	refreshResult, err := h.services.Session.RefreshSession(r.Context(), cookie.Value)
	if err != nil {
		middleware.ClearSessionCookie(w, h.cookies)
		middleware.ClearRefreshCookie(w, h.cookies)
		h.writeError(w, err)
		return
	}

	middleware.SetSessionCookie(w, h.cookies, refreshResult.SessionToken)
	middleware.SetRefreshCookie(w, h.cookies, refreshResult.RefreshToken)
	// The session goes out verbatim, like every other endpoint that returns
	// one. The hand-built subset this replaces renamed lastActiveAt to
	// lastActive and omitted activeOrgId/activeOrgRole, so a client that
	// refreshed got a different shape than the one /auth/me had just handed
	// it. Every token hash on domain.Session is json:"-", and it is the
	// caller's own session either way.
	h.writeJSON(w, http.StatusOK, map[string]any{"session": refreshResult.Session})
}

// ListSessions returns a page of the authenticated user's sessions.
func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
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
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
		return
	}
	currentSessionID := ""
	if currentSession != nil {
		currentSessionID = currentSession.ID
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"sessions":         sessions,
		"total":            total,
		"limit":            limit,
		"offset":           offset,
		"currentSessionId": currentSessionID,
	})
}

// GetAllSessions responds with all active sessions for the authenticated user.
func (h *Handler) GetAllSessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	currentSession := middleware.GetSessionFromContext(r.Context())

	sessions, err := h.services.Session.ListAll(r.Context(), user.ID)
	if err != nil {
		h.log.Error("failed to list all sessions", "err", err, "user_id", user.ID)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
		return
	}
	currentSessionID := ""
	if currentSession != nil {
		currentSessionID = currentSession.ID
	}
	h.writeJSON(w, http.StatusOK, map[string]any{
		"sessions":         sessions,
		"currentSessionId": currentSessionID,
	})
}

// RevokeSession revokes one session for the authenticated user.
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	sessionID := r.PathValue("id")

	revoked, err := h.services.Session.RevokeByIDForUser(r.Context(), sessionID, user.ID)
	if err != nil {
		h.log.Error("failed to revoke session", "err", err, "user_id", user.ID, "session_id", sessionID)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
		return
	}
	if !revoked {
		h.writeError(w, domain.NewError("session_not_found", "Session not found"))
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Session revoked"})
}

// RevokeManySessions revokes multiple sessions for the authenticated user.
func (h *Handler) RevokeManySessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var body struct {
		SessionIDs []string `json:"sessionIds"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}
	if len(body.SessionIDs) == 0 {
		h.writeError(w, domain.NewError("invalid_input", "sessionIds must not be empty"))
		return
	}
	if len(body.SessionIDs) > 100 {
		h.writeError(w, domain.NewError("invalid_input", "cannot revoke more than 100 sessions at once"))
		return
	}

	revoked, err := h.services.Session.RevokeManyForUser(r.Context(), body.SessionIDs, user.ID)
	if err != nil {
		h.log.Error("failed to revoke sessions", "err", err, "user_id", user.ID)
		h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"revoked": revoked})
}

// RevokeAllSessions revokes all other sessions for the authenticated user.
func (h *Handler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	currentSession := middleware.GetSessionFromContext(r.Context())

	if currentSession != nil {
		if err := h.services.Session.RevokeAllExcept(r.Context(), user.ID, currentSession.ID); err != nil {
			h.log.Error("failed to revoke sessions", "err", err, "user_id", user.ID)
			h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
			return
		}
	} else {
		if err := h.services.Session.RevokeAll(r.Context(), user.ID); err != nil {
			h.log.Error("failed to revoke all sessions", "err", err, "user_id", user.ID)
			h.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": "Internal server error"})
			return
		}
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Sessions revoked"})
}
