package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// bulkUserIDsBody is the shared request body for every bulk user-action
// endpoint.
type bulkUserIDsBody struct {
	UserIDs []string `json:"userIds"`
}

// BulkBanUsers bans multiple users.
func (h *Handler) BulkBanUsers(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	var body bulkUserIDsBody
	if !h.decodeJSON(w, r, &body) {
		return
	}
	result, err := h.services.Admin.BulkBanUsers(r.Context(), api.BulkUserActionInput{UserIDs: body.UserIDs, ActorID: actor.ID, ActorSessionID: actorSessionID(r)})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// BulkUnbanUsers unbans multiple users.
func (h *Handler) BulkUnbanUsers(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	var body bulkUserIDsBody
	if !h.decodeJSON(w, r, &body) {
		return
	}
	result, err := h.services.Admin.BulkUnbanUsers(r.Context(), api.BulkUserActionInput{UserIDs: body.UserIDs, ActorID: actor.ID, ActorSessionID: actorSessionID(r)})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// BulkDeleteUsers deletes multiple users.
func (h *Handler) BulkDeleteUsers(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	var body bulkUserIDsBody
	if !h.decodeJSON(w, r, &body) {
		return
	}
	result, err := h.services.Admin.BulkDeleteUsers(r.Context(), api.BulkUserActionInput{UserIDs: body.UserIDs, ActorID: actor.ID, ActorSessionID: actorSessionID(r)})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// BulkRevokeUserSessions revokes sessions for multiple users.
func (h *Handler) BulkRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	var body bulkUserIDsBody
	if !h.decodeJSON(w, r, &body) {
		return
	}
	result, err := h.services.Admin.BulkRevokeUserSessions(r.Context(), api.BulkUserActionInput{UserIDs: body.UserIDs, ActorID: actor.ID, ActorSessionID: actorSessionID(r)})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
