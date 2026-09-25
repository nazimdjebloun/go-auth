package handler

import (
	"net/http"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// GetAdminStats returns platform-wide counts for an admin dashboard —
// total/verified/banned/two-factor/never-logged-in users and active
// sessions. No params.
func (h *Handler) GetAdminStats(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	stats, err := h.services.Admin.GetStats(r.Context(), actor.ID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, stats)
}

// parseStatsRange reads and validates the required from/to RFC3339 query
// params shared by GetRegistrationTrend and GetLoginActivity.
func (h *Handler) parseStatsRange(w http.ResponseWriter, r *http.Request) (from, to time.Time, ok bool) {
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	if fromStr == "" || toStr == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_input", "message": "from and to are required"})
		return time.Time{}, time.Time{}, false
	}
	from, err := time.Parse(time.RFC3339, fromStr)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_input", "message": "from must be RFC3339"})
		return time.Time{}, time.Time{}, false
	}
	to, err = time.Parse(time.RFC3339, toStr)
	if err != nil {
		h.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_input", "message": "to must be RFC3339"})
		return time.Time{}, time.Time{}, false
	}
	return from, to, true
}

// GetRegistrationTrend returns registrations per day over [from, to] (both
// required, RFC3339) — the data behind a registrations-over-time chart.
func (h *Handler) GetRegistrationTrend(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	from, to, ok := h.parseStatsRange(w, r)
	if !ok {
		return
	}
	counts, err := h.services.Admin.GetRegistrationTrend(r.Context(), api.StatsRangeInput{
		ActorID: actor.ID, From: from, To: to,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"registrations": counts})
}

// GetLoginActivity returns successful-login counts per day over [from, to]
// (both required, RFC3339) — the data behind a GitHub-commit-style login
// heatmap. Global (every user) by default; pass userId for one user's.
func (h *Handler) GetLoginActivity(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	from, to, ok := h.parseStatsRange(w, r)
	if !ok {
		return
	}
	var userID *string
	if v := r.URL.Query().Get("userId"); v != "" {
		userID = &v
	}
	counts, err := h.services.Admin.GetLoginActivity(r.Context(), api.LoginActivityInput{
		ActorID: actor.ID, UserID: userID, From: from, To: to,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"logins": counts})
}
