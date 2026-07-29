package handler

import (
	"net/http"
	"strconv"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

func orgDisabled() bool {
	return false
}

func writeServiceError(w http.ResponseWriter, err error) {
	if ae, ok := err.(*domain.AuthError); ok {
		writeError(w, ae)
		return
	}
	writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal_error", "message": err.Error()})
}

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
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, org)
}

func (h *Handler) GetOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	orgID := r.PathValue("orgID")
	org, err := h.services.Org.GetByID(r.Context(), orgID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (h *Handler) UpdateOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
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
		OrgID: orgID,
		Name:  body.Name,
		Slug:  body.Slug,
	})
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (h *Handler) DeleteOrg(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	orgID := r.PathValue("orgID")
	if err := h.services.Org.DeleteOrg(r.Context(), orgID); err != nil {
		writeServiceError(w, err)
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

	orgs, err := h.services.Org.ListUserOrgs(r.Context(), user.ID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"orgs": orgs})
}

func (h *Handler) ListOrgMembers(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	orgID := r.PathValue("orgID")
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	members, total, err := h.services.Org.ListMembers(r.Context(), orgID, offset, limit)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"members": members,
		"total":   total,
	})
}

func (h *Handler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	if h.services.Org == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	orgID := r.PathValue("orgID")
	userID := r.PathValue("userID")
	if err := h.services.Org.RemoveMember(r.Context(), orgID, userID); err != nil {
		writeServiceError(w, err)
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
		writeServiceError(w, err)
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
	if err := h.services.Org.LeaveOrg(r.Context(), orgID, user.ID); err != nil {
		writeServiceError(w, err)
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

	if err := h.services.Org.SetActiveOrg(r.Context(), session.ID, user.ID, body.OrgID); err != nil {
		writeServiceError(w, err)
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
	if err := h.services.Org.ClearActiveOrg(r.Context(), session.ID, ""); err != nil {
		writeServiceError(w, err)
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
		writeServiceError(w, err)
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
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite accepted"})
}

func (h *Handler) ListOrgInvites(w http.ResponseWriter, r *http.Request) {
	if h.services.OrgInvite == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	orgID := r.PathValue("orgID")
	invites, err := h.services.OrgInvite.ListOrgInvites(r.Context(), orgID)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"invites": invites})
}

func (h *Handler) ResendOrgInvite(w http.ResponseWriter, r *http.Request) {
	if h.services.OrgInvite == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	inviteID := r.PathValue("inviteID")
	if err := h.services.OrgInvite.ResendOrgInviteEmail(r.Context(), inviteID); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite email resent"})
}

func (h *Handler) DeleteOrgInvite(w http.ResponseWriter, r *http.Request) {
	if h.services.OrgInvite == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found", "message": "Organizations not enabled"})
		return
	}
	inviteID := r.PathValue("inviteID")
	if err := h.services.OrgInvite.DeleteOrgInvite(r.Context(), inviteID); err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite deleted"})
}
