package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/middleware"
)

func emailActor(r *http.Request) api.EmailChangeActor {
	a := api.EmailChangeActor{SessionID: actorSessionID(r)}
	if u := middleware.GetUserFromContext(r.Context()); u != nil {
		a.UserID = u.ID
	}
	return a
}

// Email inputs are flat string objects. Parse keys before unmarshalling so
// duplicate or case-variant keys cannot select a different value downstream.
func (h *Handler) decodeEmailJSON(w http.ResponseWriter, r *http.Request, v any, allowed ...string) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	d := json.NewDecoder(r.Body)
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		h.writeError(w, domain.NewError("invalid_json", "Expected one JSON object"))
		return false
	}
	values := map[string]json.RawMessage{}
	keys := map[string]bool{}
	for _, key := range allowed {
		keys[key] = true
	}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			h.writeError(w, domain.NewError("invalid_json", "Invalid request body"))
			return false
		}
		key, ok := t.(string)
		if !ok || !keys[key] || values[key] != nil {
			h.writeError(w, domain.NewError("invalid_json", "Unknown or duplicate field"))
			return false
		}
		var value string
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil || string(raw) == "null" || json.Unmarshal(raw, &value) != nil {
			h.writeError(w, domain.NewError("invalid_json", "Fields must be strings"))
			return false
		}
		values[key] = raw
	}
	if _, err := d.Token(); err != nil {
		h.writeError(w, domain.NewError("invalid_json", "Invalid request body"))
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		h.writeError(w, domain.NewError("invalid_json", "Expected one JSON object"))
		return false
	}
	raw, err := json.Marshal(values)
	if err != nil || json.Unmarshal(raw, v) != nil {
		h.writeError(w, domain.NewError("invalid_json", "Invalid request body"))
		return false
	}
	return true
}

// RequestEmailChange mails confirmation codes to both account addresses.
func (h *Handler) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
	var input api.RequestEmailChangeInput
	if !h.decodeEmailJSON(w, r, &input, "newEmail", "password") {
		return
	}
	input.Actor = emailActor(r)
	result, err := h.services.Email.RequestEmailChange(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// ConfirmEmailChange clears browser credentials after the transaction commits.
func (h *Handler) ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	var input api.ConfirmEmailChangeInput
	if !h.decodeEmailJSON(w, r, &input, "requestId", "currentEmailCode", "newEmailCode") {
		return
	}
	input.Actor = emailActor(r)
	if err := h.services.Email.ConfirmEmailChange(r.Context(), input); err != nil {
		h.writeError(w, err)
		return
	}
	if !h.clearSessionCookies(w, r) {
		return
	}
	h.writeJSON(w, http.StatusOK, api.AuthenticationResponse{Step: api.StepSignIn, Message: "Email changed. Sign in again."})
}

// ResendEmailChange rotates only the selected mailbox's code.
func (h *Handler) ResendEmailChange(w http.ResponseWriter, r *http.Request) {
	var input api.ResendEmailChangeInput
	if !h.decodeEmailJSON(w, r, &input, "requestId", "destination") {
		return
	}
	input.Actor = emailActor(r)
	result, err := h.services.Email.ResendEmailChange(r.Context(), input)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, result)
}

// CancelEmailChange cancels a pending request in its initiating browser session.
func (h *Handler) CancelEmailChange(w http.ResponseWriter, r *http.Request) {
	if err := h.services.Email.CancelEmailChange(r.Context(), api.CancelEmailChangeInput{Actor: emailActor(r), RequestID: r.PathValue("requestID")}); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
