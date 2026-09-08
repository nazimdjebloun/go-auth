package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func (h *Handler) AdminListAuditLogs(w http.ResponseWriter, r *http.Request) {
	h.listAuditLogs(w, r, nil)
}

func (h *Handler) AdminListUserAuditLogs(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	h.listAuditLogs(w, r, &userID)
}

func (h *Handler) listAuditLogs(w http.ResponseWriter, r *http.Request, userID *string) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	var eventTypes []string
	if v := r.URL.Query().Get("event_type"); v != "" {
		eventTypes = strings.Split(v, ",")
	}

	var actorID, actorEmail, targetUserID, targetEmail, sessionID, orgID, deviceType, ip, search *string
	if v := r.URL.Query().Get("actor_id"); v != "" {
		actorID = &v
	}
	if v := r.URL.Query().Get("actorEmail"); v != "" {
		actorEmail = &v
	}
	if v := r.URL.Query().Get("target_user_id"); v != "" {
		targetUserID = &v
	}
	if v := r.URL.Query().Get("targetEmail"); v != "" {
		targetEmail = &v
	}
	if v := r.URL.Query().Get("session_id"); v != "" {
		sessionID = &v
	}
	if v := r.URL.Query().Get("org_id"); v != "" {
		orgID = &v
	}
	if v := r.URL.Query().Get("deviceType"); v != "" {
		deviceType = &v
	}
	if v := r.URL.Query().Get("ip"); v != "" {
		ip = &v
	}
	if v := r.URL.Query().Get("search"); v != "" {
		search = &v
	}

	var fromDate, toDate *time.Time
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			fromDate = &t
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			toDate = &t
		}
	}

	var success *bool
	if v := r.URL.Query().Get("success"); v == "true" {
		b := true
		success = &b
	} else if v == "false" {
		b := false
		success = &b
	}

	// The per-user route ({id} in the path) always wins over any
	// target_user_id/targetEmail passed in the query string.
	if userID != nil {
		targetUserID = userID
		targetEmail = nil
	}

	input := service.AdminListAuditLogsInput{
		ActorID:         actor.ID,
		EventTypes:      eventTypes,
		EventActorID:    actorID,
		EventActorEmail: actorEmail,
		TargetUserID:    targetUserID,
		TargetEmail:     targetEmail,
		SessionID:       sessionID,
		OrgID:           orgID,
		DeviceType:      deviceType,
		IP:              ip,
		Success:         success,
		Search:          search,
		FromDate:        fromDate,
		ToDate:          toDate,
		Offset:          offset,
		Limit:           limit,
	}

	if strings.HasSuffix(r.URL.Path, "/count") {
		n, err := h.services.Admin.CountAuditLogs(r.Context(), input)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"count": n})
		return
	}

	result, err := h.services.Admin.ListAuditLogs(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}
