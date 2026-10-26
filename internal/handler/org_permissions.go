package handler

import (
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"net/http"
)

func orgRequestActor(r *http.Request) api.OrgPermissionActor {
	actor := api.OrgPermissionActor{OrgID: r.PathValue("orgID"), SessionID: actorSessionID(r)}
	if u := middleware.GetUserFromContext(r.Context()); u != nil {
		actor.UserID = u.ID
	}
	return actor
}

// InitializeOrgPermissions is restricted to an authenticated current owner.
func (h *Handler) InitializeOrgPermissions(w http.ResponseWriter, r *http.Request) {
	if err := h.services.OrgPermissions.Initialize(r.Context(), api.InitializeOrgPermissionsInput{Actor: orgRequestActor(r)}); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// OrgLibraryPermissions returns only the fixed catalog; it never queries definitions.
func (h *Handler) OrgLibraryPermissions(w http.ResponseWriter, r *http.Request) {
	if err := h.services.OrgPermissions.RequireOwner(r.Context(), orgRequestActor(r)); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"permissions": h.services.OrgPermissions.LibraryPermissionCatalog()})
}

// UpdateOrgLibraryPermissions atomically installs/removes a selected catalog batch.
func (h *Handler) UpdateOrgLibraryPermissions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Create []string `json:"create"`
		Delete []string `json:"delete"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.OrgPermissions.UpdateLibraryPermissions(r.Context(), api.UpdateOrgLibraryPermissionsInput{Actor: orgRequestActor(r), Create: body.Create, Delete: body.Delete})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// ListOrgPermissions lists installed definitions, independently of the catalog.
func (h *Handler) ListOrgPermissions(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := h.appPage(w, r)
	if !ok {
		return
	}
	result, err := h.services.OrgPermissions.ListPermissions(r.Context(), api.ListOrgPermissionsInput{Actor: orgRequestActor(r), Limit: limit, Offset: offset})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"permissions": result})
}

// CreateOrgPermission defines a business permission without granting it.
func (h *Handler) CreateOrgPermission(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.OrgPermissions.CreatePermission(r.Context(), api.CreateOrgPermissionInput{Actor: orgRequestActor(r), Key: body.Key, Name: body.Name, Description: body.Description})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, result)
}

// UpdateOrgPermission changes business metadata or enabled state using a revision.
func (h *Handler) UpdateOrgPermission(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedRevision uint64  `json:"expectedRevision"`
		Name             *string `json:"name"`
		Description      *string `json:"description"`
		IsEnabled        *bool   `json:"isEnabled"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.OrgPermissions.UpdatePermission(r.Context(), api.UpdateOrgPermissionInput{Actor: orgRequestActor(r), PermissionID: r.PathValue("permissionID"), ExpectedRevision: body.ExpectedRevision, Name: body.Name, Description: body.Description, IsEnabled: body.IsEnabled})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// DeleteOrgPermission refuses referenced and library definitions.
func (h *Handler) DeleteOrgPermission(w http.ResponseWriter, r *http.Request) {
	revision, ok := h.appExpectedRevision(w, r)
	if !ok {
		return
	}
	if err := h.services.OrgPermissions.DeletePermission(r.Context(), api.DeleteOrgPermissionInput{Actor: orgRequestActor(r), PermissionID: r.PathValue("permissionID"), ExpectedRevision: revision}); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListOrgRoles includes the explicit grant keys for each role.
func (h *Handler) ListOrgRoles(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := h.appPage(w, r)
	if !ok {
		return
	}
	result, err := h.services.OrgPermissions.ListRoles(r.Context(), api.ListOrgRolesInput{Actor: orgRequestActor(r), Limit: limit, Offset: offset})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"roles": result})
}

// CreateOrgRole creates one custom role and its initial explicit grant set.
func (h *Handler) CreateOrgRole(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug           string   `json:"slug"`
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		PermissionKeys []string `json:"permissionKeys"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.OrgPermissions.CreateRole(r.Context(), api.CreateOrgRoleInput{Actor: orgRequestActor(r), Slug: body.Slug, Name: body.Name, Description: body.Description, PermissionKeys: body.PermissionKeys})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, result)
}

// UpdateOrgRole changes custom metadata or enabled state.
func (h *Handler) UpdateOrgRole(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedRevision uint64  `json:"expectedRevision"`
		Name             *string `json:"name"`
		Description      *string `json:"description"`
		IsEnabled        *bool   `json:"isEnabled"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.OrgPermissions.UpdateRole(r.Context(), api.UpdateOrgRoleInput{Actor: orgRequestActor(r), RoleID: r.PathValue("roleID"), ExpectedRevision: body.ExpectedRevision, Name: body.Name, Description: body.Description, IsEnabled: body.IsEnabled})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// SetOrgRolePermissions replaces the complete grant set, including an empty set.
func (h *Handler) SetOrgRolePermissions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedRevision uint64    `json:"expectedRevision"`
		PermissionKeys   *[]string `json:"permissionKeys"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	if body.PermissionKeys == nil {
		h.writeError(w, domain.NewError("invalid_input", "permissionKeys must be an array; use [] to clear grants"))
		return
	}
	result, err := h.services.OrgPermissions.SetRolePermissions(r.Context(), api.SetOrgRolePermissionsInput{Actor: orgRequestActor(r), RoleID: r.PathValue("roleID"), ExpectedRevision: body.ExpectedRevision, PermissionKeys: *body.PermissionKeys})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// DeleteOrgRole refuses protected, default and assigned roles.
func (h *Handler) DeleteOrgRole(w http.ResponseWriter, r *http.Request) {
	revision, ok := h.appExpectedRevision(w, r)
	if !ok {
		return
	}
	if err := h.services.OrgPermissions.DeleteRole(r.Context(), api.DeleteOrgRoleInput{Actor: orgRequestActor(r), RoleID: r.PathValue("roleID"), ExpectedRevision: revision}); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetOrgMemberRole reports the current role and assignment revision.
func (h *Handler) GetOrgMemberRole(w http.ResponseWriter, r *http.Request) {
	result, err := h.services.OrgPermissions.GetMemberRole(r.Context(), api.GetOrgMemberRoleInput{Actor: orgRequestActor(r), UserID: r.PathValue("userID")})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// GetOrgMemberAccess inspects a target account using the authenticated actor.
func (h *Handler) GetOrgMemberAccess(w http.ResponseWriter, r *http.Request) {
	result, err := h.services.OrgPermissions.ListEffectivePermissions(r.Context(), api.ListOrgEffectivePermissionsInput{
		Actor:  orgRequestActor(r),
		UserID: r.PathValue("userID"),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// SetOrgMemberRole replaces exactly one role assignment.
func (h *Handler) SetOrgMemberRole(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RoleID                     string `json:"roleId"`
		ExpectedRoleRevision       uint64 `json:"expectedRoleRevision"`
		ExpectedAssignmentRevision uint64 `json:"expectedAssignmentRevision"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.OrgPermissions.SetMemberRole(r.Context(), api.SetOrgMemberRoleInput{Actor: orgRequestActor(r), UserID: r.PathValue("userID"), RoleID: body.RoleID, ExpectedRoleRevision: body.ExpectedRoleRevision, ExpectedAssignmentRevision: body.ExpectedAssignmentRevision})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// OrgAccess exposes informational current access for the authenticated account.
func (h *Handler) OrgAccess(w http.ResponseWriter, r *http.Request) {
	result, err := h.services.OrgPermissions.ListEffectivePermissions(r.Context(), api.ListOrgEffectivePermissionsInput{Actor: orgRequestActor(r)})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
