package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

// ListSessions returns active sessions across every user — the admin-wide
// incident-response view. Supports the same offset/limit as ListUsers plus
// userId/ip/search/date-range filters and an orderBy/orderDirection sort.
func (h *Handler) AdminListSessions(w http.ResponseWriter, r *http.Request) {
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

	var userID *string
	if v := r.URL.Query().Get("userId"); v != "" {
		userID = &v
	}
	var ip *string
	if v := r.URL.Query().Get("ip"); v != "" {
		ip = &v
	}
	var search *string
	if v := r.URL.Query().Get("search"); v != "" {
		search = &v
	}

	parseTime := func(param string) *time.Time {
		v := r.URL.Query().Get(param)
		if v == "" {
			return nil
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil
		}
		return &t
	}

	orderBy := r.URL.Query().Get("orderBy")
	if orderBy != "created_at" && orderBy != "expires_at" && orderBy != "last_active_at" {
		orderBy = "created_at"
	}
	orderDirection := r.URL.Query().Get("orderDirection")
	if orderDirection != "asc" && orderDirection != "desc" {
		orderDirection = "desc"
	}

	input := service.AdminListSessionsInput{
		ActorID:          actor.ID,
		UserID:           userID,
		IP:               ip,
		Search:           search,
		CreatedAfter:     parseTime("createdAfter"),
		CreatedBefore:    parseTime("createdBefore"),
		ExpiresAfter:     parseTime("expiresAfter"),
		ExpiresBefore:    parseTime("expiresBefore"),
		LastActiveAfter:  parseTime("lastActiveAfter"),
		LastActiveBefore: parseTime("lastActiveBefore"),
		OrderBy:          orderBy,
		OrderDirection:   orderDirection,
		Offset:           offset,
		Limit:            limit,
	}

	if strings.HasSuffix(r.URL.Path, "/count") {
		n, err := h.services.Admin.CountSessions(r.Context(), input)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"count": n})
		return
	}

	result, err := h.services.Admin.ListSessions(r.Context(), input)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
