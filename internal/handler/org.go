package handler

import (
	"net/http"
	"strconv"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

func (h *Handler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	org, err := h.services.Org.CreateOrg(r.Context(), service.CreateOrgInput{
		Name:    body.Name,
		Slug:    body.Slug,
		OwnerID: user.ID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, org)
}

func (h *Handler) GetOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	org, err := h.services.Org.GetByID(r.Context(), service.GetOrgInput{OrgID: orgID, ActorID: user.ID})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (h *Handler) UpdateOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")

	var body struct {
		Name *string `json:"name"`
		Slug *string `json:"slug"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	org, err := h.services.Org.UpdateOrg(r.Context(), service.UpdateOrgInput{
		OrgID:   orgID,
		Name:    body.Name,
		Slug:    body.Slug,
		ActorID: user.ID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (h *Handler) DeleteOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	if err := h.services.Org.DeleteOrg(r.Context(), service.DeleteOrgInput{OrgID: orgID, ActorID: user.ID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Organization deleted"})
}

func (h *Handler) ListUserOrgs(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
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

	role, ok := parseOrgRole(w, r)
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

	result, err := h.services.Org.ListUserOrgs(r.Context(), service.ListUserOrgsInput{
		UserID: user.ID, Offset: offset, Limit: limit, Search: search, Role: role,
		OrderBy: orderBy, OrderDirection: orderDirection,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// CountUserOrgs — GET /auth/orgs/count. The total for ListUserOrgs, on its
// own call so a paginated org list doesn't run a COUNT(*) per page.
func (h *Handler) CountUserOrgs(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var search *string
	if s := r.URL.Query().Get("search"); s != "" {
		search = &s
	}

	role, ok := parseOrgRole(w, r)
	if !ok {
		return
	}

	n, err := h.services.Org.CountUserOrgs(r.Context(), service.ListUserOrgsInput{
		UserID: user.ID, Search: search, Role: role,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n})
}

func (h *Handler) ListOrgMembers(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
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

	role, ok := parseOrgRole(w, r)
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

	result, err := h.services.Org.ListMembers(r.Context(), service.ListMembersInput{
		OrgID: orgID, ActorID: user.ID, Offset: offset, Limit: limit,
		Role: role, Search: search, OrderBy: orderBy, OrderDirection: orderDirection,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// CountOrgMembers — GET /auth/orgs/{orgID}/members/count. The total for
// ListOrgMembers; same membership check, no COUNT(*) per page.
func (h *Handler) CountOrgMembers(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")

	var search *string
	if s := r.URL.Query().Get("search"); s != "" {
		search = &s
	}

	role, ok := parseOrgRole(w, r)
	if !ok {
		return
	}

	n, err := h.services.Org.CountMembers(r.Context(), service.ListMembersInput{
		OrgID: orgID, ActorID: user.ID, Role: role, Search: search,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n})
}

func (h *Handler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	userID := r.PathValue("userID")
	if err := h.services.Org.RemoveMember(r.Context(), service.RemoveMemberInput{OrgID: orgID, UserID: userID, ActorID: actor.ID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Member removed"})
}

func (h *Handler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	userID := r.PathValue("userID")

	var body struct {
		Role string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Org.UpdateMemberRole(r.Context(), service.UpdateMemberRoleInput{
		OrgID:   orgID,
		UserID:  userID,
		NewRole: domain.OrgRole(body.Role),
		ActorID: actor.ID,
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Role updated"})
}

func (h *Handler) LeaveOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	if err := h.services.Org.LeaveOrg(r.Context(), service.LeaveOrgInput{OrgID: orgID, UserID: user.ID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Left organization"})
}

func (h *Handler) SetActiveOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	session := middleware.GetSessionFromContext(r.Context())
	if user == nil || session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var body struct {
		OrgID string `json:"orgId"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	if err := h.services.Org.SetActiveOrg(r.Context(), service.SetActiveOrgInput{SessionID: session.ID, UserID: user.ID, OrgID: body.OrgID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Active org updated"})
}

func (h *Handler) ClearActiveOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	session := middleware.GetSessionFromContext(r.Context())
	if session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	if err := h.services.Org.ClearActiveOrg(r.Context(), service.ClearActiveOrgInput{SessionID: session.ID}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Active org cleared"})
}

func (h *Handler) CreateOrgInvite(w http.ResponseWriter, r *http.Request) {
	if h.services.OrgInvite == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")

	var body struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	invite, err := h.services.OrgInvite.CreateOrgInvite(r.Context(), service.CreateOrgInviteInput{
		OrgID:     orgID,
		Email:     body.Email,
		Role:      domain.OrgRole(body.Role),
		InvitedBy: user.ID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, invite)
}

func (h *Handler) AcceptOrgInvite(w http.ResponseWriter, r *http.Request) {
	if h.services.OrgInvite == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var body struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_code", "message": "Invite code is required"})
		return
	}

	if err := h.services.OrgInvite.AcceptInvite(r.Context(), service.AcceptInviteInput{
		UserID:  user.ID,
		RawCode: body.Code,
	}); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite accepted"})
}

func (h *Handler) ListOrgInvites(w http.ResponseWriter, r *http.Request) {
	if h.services.OrgInvite == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
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

	role, ok := parseOrgRole(w, r)
	if !ok {
		return
	}

	var status *string
	if s := r.URL.Query().Get("status"); s == "pending" || s == "expired" {
		status = &s
	}

	orderBy := r.URL.Query().Get("orderBy")
	if orderBy != "created_at" && orderBy != "expires_at" && orderBy != "email" && orderBy != "role" {
		orderBy = "created_at"
	}

	orderDirection := r.URL.Query().Get("orderDirection")
	if orderDirection != "asc" && orderDirection != "desc" {
		orderDirection = "desc"
	}

	result, err := h.services.OrgInvite.ListOrgInvites(r.Context(), service.ListOrgInvitesInput{
		OrgID: orgID, ActorID: user.ID, Offset: offset, Limit: limit,
		Role: role, Status: status, Search: search, OrderBy: orderBy, OrderDirection: orderDirection,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// CountOrgInvites — GET /auth/orgs/{orgID}/invites/count. The total for
// ListOrgInvites, split out so a paginated invite table doesn't run a
// COUNT(*) per page. Same org-admin access check as the list.
func (h *Handler) CountOrgInvites(w http.ResponseWriter, r *http.Request) {
	if h.services.OrgInvite == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")

	var search *string
	if s := r.URL.Query().Get("search"); s != "" {
		search = &s
	}

	role, ok := parseOrgRole(w, r)
	if !ok {
		return
	}

	var status *string
	if s := r.URL.Query().Get("status"); s == "pending" || s == "expired" {
		status = &s
	}

	n, err := h.services.OrgInvite.CountOrgInvites(r.Context(), service.ListOrgInvitesInput{
		OrgID: orgID, ActorID: user.ID, Role: role, Status: status, Search: search,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n})
}

func (h *Handler) ResendOrgInvite(w http.ResponseWriter, r *http.Request) {
	if h.services.OrgInvite == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	inviteID := r.PathValue("inviteID")
	if err := h.services.OrgInvite.ResendOrgInviteEmail(r.Context(), orgID, inviteID, user.ID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite email resent"})
}

func (h *Handler) DeleteOrgInvite(w http.ResponseWriter, r *http.Request) {
	if h.services.OrgInvite == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	orgID := r.PathValue("orgID")
	inviteID := r.PathValue("inviteID")
	if err := h.services.OrgInvite.DeleteOrgInvite(r.Context(), orgID, inviteID, user.ID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite deleted"})
}
