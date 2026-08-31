package handler

import (
	"context"
	"net/http"
	"strconv"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/service"
)

func (h *Handler) GetInviteInfo(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, domain.NewError("missing_token", "Token is required"))
		return
	}

	invite, err := h.services.Invite.GetInviteByToken(r.Context(), token)
	if err != nil {
		writeError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"email": invite.Email})
}

func (h *Handler) InviteRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code            string `json:"code"`
		Name            string `json:"name"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Invite.CompleteInviteRegistration(r.Context(), service.CompleteInviteInput{
		Code:            body.Code,
		Name:            body.Name,
		Password:        body.Password,
		ConfirmPassword: body.ConfirmPassword,
		IP:              extractIP(r.RemoteAddr),
		UserAgent:       r.UserAgent(),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	if result.RequiresTwoFactor {
		h.writeTwoFactorChallenge(w, http.StatusCreated, result.User, result.CodeSent, result.TwoFactorChallenge, result.TwoFactorExpiresAt, result.BindingToken())
		return
	}

	middleware.SetSessionCookie(w, h.services.Session.Config(), result.SessionToken)
	middleware.SetRefreshCookie(w, h.services.Session.Config(), result.RefreshToken)
	middleware.RotateCSRFToken(w, h.csrfTokenCfg)
	result.SessionToken = ""
	result.RefreshToken = ""
	writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}

	var body struct {
		Email string `json:"email"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	result, err := h.services.Invite.CreateInvite(r.Context(), service.CreateInviteInput{
		Email:   body.Email,
		AdminID: user.ID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *Handler) ListInvites(w http.ResponseWriter, r *http.Request) {
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

	orderBy := r.URL.Query().Get("orderBy")
	if orderBy != "created_at" && orderBy != "expires_at" && orderBy != "email" && orderBy != "status" {
		orderBy = "created_at"
	}
	orderDirection := r.URL.Query().Get("orderDirection")
	if orderDirection != "asc" && orderDirection != "desc" {
		orderDirection = "desc"
	}

	invites, err := h.services.Invite.ListInvites(r.Context(), service.ListInvitesInput{
		ActorID:        actor.ID,
		Offset:         offset,
		Limit:          limit,
		Search:         r.URL.Query().Get("search"),
		Status:         r.URL.Query().Get("status"),
		OrderBy:        orderBy,
		OrderDirection: orderDirection,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": invites})
}

// CountInvites — GET /admin/invites/count
func (h *Handler) CountInvites(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	n, err := h.services.Invite.CountInvites(r.Context(), service.ListInvitesInput{
		ActorID: actor.ID,
		Search:  r.URL.Query().Get("search"),
		Status:  r.URL.Query().Get("status"),
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": n})
}

func (h *Handler) HardDeleteInvite(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	inviteID := r.PathValue("id")
	if err := h.services.Invite.HardDeleteInvite(r.Context(), inviteID, actor.ID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite deleted"})
}

func (h *Handler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	inviteID := r.PathValue("id")
	if err := h.services.Invite.RevokeInvite(r.Context(), inviteID, actor.ID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite revoked"})
}

func (h *Handler) ResendInvite(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	inviteID := r.PathValue("id")
	if err := h.services.Invite.ResendInviteEmail(r.Context(), inviteID, actor.ID); err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Invite resent"})
}

// bulkInviteIDsBody is the shared request body for the ID-keyed bulk invite
// endpoints.
type bulkInviteIDsBody struct {
	InviteIDs []string `json:"inviteIds"`
}

func (h *Handler) BulkSendInvites(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	var body struct {
		Emails []string `json:"emails"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	result, err := h.services.Invite.BulkSendInvites(r.Context(), service.BulkInviteEmailsInput{
		Emails: body.Emails, ActorID: actor.ID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) BulkResendInvites(w http.ResponseWriter, r *http.Request) {
	h.bulkInviteAction(w, r, h.services.Invite.BulkResendInvites)
}

func (h *Handler) BulkRevokeInvites(w http.ResponseWriter, r *http.Request) {
	h.bulkInviteAction(w, r, h.services.Invite.BulkRevokeInvites)
}

func (h *Handler) BulkDeleteInvites(w http.ResponseWriter, r *http.Request) {
	h.bulkInviteAction(w, r, h.services.Invite.BulkDeleteInvites)
}

// bulkInviteAction is the shared decode/authenticate/dispatch for the
// ID-keyed bulk invite endpoints, which differ only in the service call.
func (h *Handler) bulkInviteAction(
	w http.ResponseWriter,
	r *http.Request,
	run func(context.Context, service.BulkInviteIDsInput) (*service.BulkInviteResult, error),
) {
	actor := middleware.GetUserFromContext(r.Context())
	if actor == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized", "message": "Not authenticated"})
		return
	}
	var body bulkInviteIDsBody
	if !decodeJSON(w, r, &body) {
		return
	}
	result, err := run(r.Context(), service.BulkInviteIDsInput{
		InviteIDs: body.InviteIDs, ActorID: actor.ID,
	})
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
