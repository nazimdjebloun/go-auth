package handler

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

// bulkUserIDsBody is the shared request body for every bulk user-action
// endpoint.
type bulkUserIDsBody struct {
	UserIDs []string `json:"userIds"`
}

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
	result, err := h.services.Admin.BulkBanUsers(r.Context(), service.BulkUserActionInput{UserIDs: body.UserIDs, ActorID: actor.ID})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

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
	result, err := h.services.Admin.BulkUnbanUsers(r.Context(), service.BulkUserActionInput{UserIDs: body.UserIDs, ActorID: actor.ID})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

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
	result, err := h.services.Admin.BulkDeleteUsers(r.Context(), service.BulkUserActionInput{UserIDs: body.UserIDs, ActorID: actor.ID})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

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
	result, err := h.services.Admin.BulkRevokeUserSessions(r.Context(), service.BulkUserActionInput{UserIDs: body.UserIDs, ActorID: actor.ID})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
