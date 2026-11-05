package handler

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/httperr"
)

// expectedRevision accepts one strong, positive decimal revision tag. Wildcards,
// weak tags and lists cannot stand in for the exact state the caller reviewed.
func (h *Handler) expectedRevision(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	values := r.Header.Values("If-Match")
	if len(values) == 1 && !r.URL.Query().Has("expectedRevision") {
		value := strings.TrimSpace(values[0])
		if len(value) > 2 && value[0] == '"' && value[len(value)-1] == '"' {
			raw := value[1 : len(value)-1]
			revision, err := strconv.ParseUint(raw, 10, 64)
			if err == nil && revision > 0 && strconv.FormatUint(revision, 10) == raw {
				return revision, true
			}
		}
	}
	h.writeError(w, domain.NewError("invalid_input", `If-Match must contain one quoted positive revision, for example "1"; expectedRevision query parameters are not accepted`))
	return 0, false
}

// Service conflicts remain transport-neutral. An HTTP If-Match mismatch is a
// failed precondition, retaining the existing machine-readable conflict code.
func (h *Handler) writeRevisionError(w http.ResponseWriter, err error) {
	for _, conflict := range []*domain.AuthError{domain.ErrAppAuthorizationConflict, domain.ErrOrgAuthorizationConflict} {
		if errors.Is(err, conflict) {
			httperr.Write(w, http.StatusPreconditionFailed, conflict.Code, conflict.Message, h.log)
			return
		}
	}
	h.writeError(w, err)
}
