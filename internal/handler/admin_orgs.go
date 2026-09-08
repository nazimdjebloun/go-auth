package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

// Platform-admin oversight of orgs: list/view/mutate any organization
// regardless of the caller's own membership in it. These call OrgService
// (not AdminService) — see service/org_admin.go for why. Every handler here
// mirrors the h.services.Org == nil guard used by the self-service org
// handlers in org.go, even though in practice these routes are only ever
// mounted when Org is non-nil (Mount only registers them inside
// `if a.orgService != nil`).

func (h *Handler) AdminListOrgs(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	var limit *int
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = &n
		}
	}

	var search *string
	if s := r.URL.Query().Get("search"); s != "" {
		search = &s
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
	if orderBy != "name" && orderBy != "created_at" && orderBy != "member_count" {
		orderBy = "name"
	}
	orderDirection := r.URL.Query().Get("orderDirection")
	if orderDirection != "asc" && orderDirection != "desc" {
		orderDirection = "asc"
	}

	input := service.AdminListOrgsInput{
		ActorID:        actor.ID,
		Search:         search,
		CreatedAfter:   parseTime("createdAfter"),
		CreatedBefore:  parseTime("createdBefore"),
		OrderBy:        orderBy,
		OrderDirection: orderDirection,
		Offset:         offset,
		Limit:          limit,
	}

	if strings.HasSuffix(r.URL.Path, "/count") {
		n, err := h.services.Org.CountOrgs(r.Context(), input)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"count": n})
		return
	}

	result, err := h.services.Org.AdminListOrgs(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *Handler) AdminGetOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	org, err := h.services.Org.AdminGetOrg(r.Context(), service.AdminGetOrgInput{OrgID: orgID, ActorID: actor.ID})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, org)
}

func (h *Handler) AdminListOrgMembers(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	var limit *int
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = &n
		}
	}

	var search *string
	if s := r.URL.Query().Get("search"); s != "" {
		search = &s
	}

	role, ok := h.parseOrgRole(w, r)
	if !ok {
		return
	}

	orderBy := r.URL.Query().Get("orderBy")
	if orderBy != "joined_at" && orderBy != "role" && orderBy != "name" && orderBy != "email" {
		orderBy = "joined_at"
	}
	orderDirection := r.URL.Query().Get("orderDirection")
	if orderDirection != "asc" && orderDirection != "desc" {
		orderDirection = "asc"
	}

	input := service.AdminListOrgMembersInput{
		OrgID: orgID, ActorID: actor.ID, Offset: offset, Limit: limit,
		Role: role, Search: search, OrderBy: orderBy, OrderDirection: orderDirection,
	}

	if strings.HasSuffix(r.URL.Path, "/count") {
		n, err := h.services.Org.AdminCountOrgMembers(r.Context(), input)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"count": n})
		return
	}

	result, err := h.services.Org.AdminListOrgMembers(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

func (h *Handler) AdminAddOrgMember(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")

	var body struct {
		UserID string `json:"userId"`
		Role   string `json:"role"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Org.AdminAddMember(r.Context(), service.AdminAddMemberInput{
		OrgID:   orgID,
		UserID:  body.UserID,
		Role:    domain.OrgRole(body.Role),
		ActorID: actor.ID,
	}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, map[string]string{"message": "Member added"})
}

func (h *Handler) AdminDeleteOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	if err := h.services.Org.AdminDeleteOrg(r.Context(), service.AdminOrgActionInput{OrgID: orgID, ActorID: actor.ID}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Organization deleted"})
}

func (h *Handler) AdminRemoveOrgMember(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	userID := r.PathValue("userID")
	if err := h.services.Org.AdminRemoveMember(r.Context(), service.AdminRemoveMemberInput{OrgID: orgID, UserID: userID, ActorID: actor.ID}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Member removed"})
}

func (h *Handler) AdminUpdateOrgMemberRole(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	userID := r.PathValue("userID")

	var body struct {
		Role string `json:"role"`
	}
	if !h.decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Org.AdminUpdateMemberRole(r.Context(), service.AdminUpdateMemberRoleInput{
		OrgID:   orgID,
		UserID:  userID,
		NewRole: domain.OrgRole(body.Role),
		ActorID: actor.ID,
	}); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Role updated"})
}

func (h *Handler) AdminListUserOrgs(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		h.writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		h.writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	userID := r.PathValue("id")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	var limit *int
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = &n
		}
	}

	var search *string
	if s := r.URL.Query().Get("search"); s != "" {
		search = &s
	}

	role, ok := h.parseOrgRole(w, r)
	if !ok {
		return
	}

	orderBy := r.URL.Query().Get("orderBy")
	if orderBy != "name" && orderBy != "created_at" && orderBy != "member_count" {
		orderBy = "name"
	}
	orderDirection := r.URL.Query().Get("orderDirection")
	if orderDirection != "asc" && orderDirection != "desc" {
		orderDirection = "asc"
	}

	input := service.AdminListUserOrgsInput{
		ActorID:        actor.ID,
		UserID:         userID,
		Search:         search,
		Role:           role,
		OrderBy:        orderBy,
		OrderDirection: orderDirection,
		Offset:         offset,
		Limit:          limit,
	}

	if strings.HasSuffix(r.URL.Path, "/count") {
		n, err := h.services.Org.AdminCountUserOrgs(r.Context(), input)
		if err != nil {
			h.writeError(w, err)
			return
		}
		h.writeJSON(w, http.StatusOK, map[string]any{"count": n})
		return
	}

	result, err := h.services.Org.AdminListUserOrgs(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
