package handler

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func actorSessionID(r *http.Request) string {
	if s := middleware.GetSessionFromContext(r.Context()); s != nil {
		return s.ID
	}
	return ""
}

func optionalAppRoleID(r *http.Request) *string {
	if id := r.URL.Query().Get("appRoleId"); id != "" {
		return &id
	}
	return nil
}

func appRequestActor(r *http.Request) api.AppPermissionActor {
	actor := api.AppPermissionActor{SessionID: actorSessionID(r)}
	if u := middleware.GetUserFromContext(r.Context()); u != nil {
		actor.UserID = u.ID
	}
	return actor
}

// Management input is bounded, strict, and never contains a trusted actor.
func (h *Handler) decodeAppJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		h.writeError(w, domain.NewError("invalid_json", "Invalid request body"))
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		h.writeError(w, domain.NewError("invalid_json", "Expected one JSON object"))
		return false
	}
	return true
}

func (h *Handler) appPage(w http.ResponseWriter, r *http.Request) (int, int, bool) {
	var values [2]int
	for i, key := range []string{"limit", "offset"} {
		if raw := r.URL.Query().Get(key); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil || v < 0 {
				h.writeError(w, domain.NewError("invalid_input", "Invalid pagination"))
				return 0, 0, false
			}
			values[i] = v
		}
	}
	return values[0], values[1], true
}

func (h *Handler) appExpectedRevision(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	v, err := strconv.ParseUint(r.URL.Query().Get("expectedRevision"), 10, 64)
	if err != nil || v == 0 {
		h.writeError(w, domain.NewError("invalid_input", "expectedRevision must be positive"))
		return 0, false
	}
	return v, true
}

// AppLibraryPermissions returns only the fixed catalog; it never queries definitions.
func (h *Handler) AppLibraryPermissions(w http.ResponseWriter, r *http.Request) {
	if err := h.services.AppPermissions.RequireProtectedAdmin(r.Context(), appRequestActor(r)); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"permissions": h.services.AppPermissions.LibraryPermissionCatalog()})
}

// UpdateAppLibraryPermissions atomically installs/removes a selected catalog batch.
func (h *Handler) UpdateAppLibraryPermissions(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Create []string `json:"create"`
		Delete []string `json:"delete"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.AppPermissions.UpdateLibraryPermissions(r.Context(), api.UpdateAppLibraryPermissionsInput{Actor: appRequestActor(r), Create: body.Create, Delete: body.Delete})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// ListAppPermissions lists installed definitions, independently of the catalog.
func (h *Handler) ListAppPermissions(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := h.appPage(w, r)
	if !ok {
		return
	}
	result, err := h.services.AppPermissions.ListPermissions(r.Context(), api.ListAppPermissionsInput{Actor: appRequestActor(r), Limit: limit, Offset: offset})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"permissions": result})
}

// CreateAppPermission defines a business permission without granting it.
func (h *Handler) CreateAppPermission(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.AppPermissions.CreatePermission(r.Context(), api.CreateAppPermissionInput{Actor: appRequestActor(r), Key: body.Key, Name: body.Name, Description: body.Description})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, result)
}

// UpdateAppPermission changes business metadata or enabled state using a revision.
func (h *Handler) UpdateAppPermission(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedRevision uint64  `json:"expectedRevision"`
		Name             *string `json:"name"`
		Description      *string `json:"description"`
		IsEnabled        *bool   `json:"isEnabled"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.AppPermissions.UpdatePermission(r.Context(), api.UpdateAppPermissionInput{Actor: appRequestActor(r), PermissionID: r.PathValue("permissionID"), ExpectedRevision: body.ExpectedRevision, Name: body.Name, Description: body.Description, IsEnabled: body.IsEnabled})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// DeleteAppPermission refuses referenced and library definitions.
func (h *Handler) DeleteAppPermission(w http.ResponseWriter, r *http.Request) {
	revision, ok := h.appExpectedRevision(w, r)
	if !ok {
		return
	}
	if err := h.services.AppPermissions.DeletePermission(r.Context(), api.DeleteAppPermissionInput{Actor: appRequestActor(r), PermissionID: r.PathValue("permissionID"), ExpectedRevision: revision}); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListAppRoles includes the explicit grant keys for each role.
func (h *Handler) ListAppRoles(w http.ResponseWriter, r *http.Request) {
	limit, offset, ok := h.appPage(w, r)
	if !ok {
		return
	}
	result, err := h.services.AppPermissions.ListRoles(r.Context(), api.ListAppRolesInput{Actor: appRequestActor(r), Limit: limit, Offset: offset})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]any{"roles": result})
}

// CreateAppRole creates one custom role and its initial explicit grant set.
func (h *Handler) CreateAppRole(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Slug           string   `json:"slug"`
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		PermissionKeys []string `json:"permissionKeys"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.AppPermissions.CreateRole(r.Context(), api.CreateAppRoleInput{Actor: appRequestActor(r), Slug: body.Slug, Name: body.Name, Description: body.Description, PermissionKeys: body.PermissionKeys})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusCreated, result)
}

// UpdateAppRole changes custom metadata or enabled state.
func (h *Handler) UpdateAppRole(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ExpectedRevision uint64  `json:"expectedRevision"`
		Name             *string `json:"name"`
		Description      *string `json:"description"`
		IsEnabled        *bool   `json:"isEnabled"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.AppPermissions.UpdateRole(r.Context(), api.UpdateAppRoleInput{Actor: appRequestActor(r), RoleID: r.PathValue("roleID"), ExpectedRevision: body.ExpectedRevision, Name: body.Name, Description: body.Description, IsEnabled: body.IsEnabled})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// SetAppRolePermissions replaces the complete grant set, including an empty set.
func (h *Handler) SetAppRolePermissions(w http.ResponseWriter, r *http.Request) {
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
	result, err := h.services.AppPermissions.SetRolePermissions(r.Context(), api.SetAppRolePermissionsInput{Actor: appRequestActor(r), RoleID: r.PathValue("roleID"), ExpectedRevision: body.ExpectedRevision, PermissionKeys: *body.PermissionKeys})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// DeleteAppRole refuses protected, default and assigned roles.
func (h *Handler) DeleteAppRole(w http.ResponseWriter, r *http.Request) {
	revision, ok := h.appExpectedRevision(w, r)
	if !ok {
		return
	}
	if err := h.services.AppPermissions.DeleteRole(r.Context(), api.DeleteAppRoleInput{Actor: appRequestActor(r), RoleID: r.PathValue("roleID"), ExpectedRevision: revision}); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetAppUserRole reports the current role and assignment revision.
func (h *Handler) GetAppUserRole(w http.ResponseWriter, r *http.Request) {
	result, err := h.services.AppPermissions.GetUserRole(r.Context(), api.GetAppUserRoleInput{Actor: appRequestActor(r), UserID: r.PathValue("id")})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// GetAppUserAccess inspects a target account using the authenticated actor.
func (h *Handler) GetAppUserAccess(w http.ResponseWriter, r *http.Request) {
	result, err := h.services.AppPermissions.ListEffectivePermissions(r.Context(), api.ListAppEffectivePermissionsInput{
		Actor:  appRequestActor(r),
		UserID: r.PathValue("id"),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// SetAppUserRole replaces exactly one role assignment.
func (h *Handler) SetAppUserRole(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RoleID                     string `json:"roleId"`
		ExpectedRoleRevision       uint64 `json:"expectedRoleRevision"`
		ExpectedAssignmentRevision uint64 `json:"expectedAssignmentRevision"`
	}
	if !h.decodeAppJSON(w, r, &body) {
		return
	}
	result, err := h.services.AppPermissions.SetUserRole(r.Context(), api.SetAppUserRoleInput{Actor: appRequestActor(r), UserID: r.PathValue("id"), RoleID: body.RoleID, ExpectedRoleRevision: body.ExpectedRoleRevision, ExpectedAssignmentRevision: body.ExpectedAssignmentRevision})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// AppAccess exposes informational current access for the authenticated account.
func (h *Handler) AppAccess(w http.ResponseWriter, r *http.Request) {
	result, err := h.services.AppPermissions.ListEffectivePermissions(r.Context(), api.ListAppEffectivePermissionsInput{Actor: appRequestActor(r)})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}
