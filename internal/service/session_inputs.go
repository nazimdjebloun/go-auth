package service

import (
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// NormalizeSessionPage supplies one pagination policy for session services and
// HTTP response metadata: nonpositive limits use 20, limits cap at 100, and
// negative offsets start at the first row.
func NormalizeSessionPage(input api.SessionPageInput) api.SessionPageInput {
	input.Offset = max(input.Offset, 0)
	if input.Limit <= 0 {
		input.Limit = 20
	}
	input.Limit = min(input.Limit, 100)
	return input
}

// ValidateSessionRevocation checks the batch input before any database mutation.
// Transports can use the same check to map client errors before delegation.
func ValidateSessionRevocation(sessionIDs []string) error {
	if len(sessionIDs) == 0 {
		return domain.NewError("invalid_input", "sessionIds must not be empty")
	}
	if len(sessionIDs) > 100 {
		return domain.NewError("invalid_input", "cannot revoke more than 100 sessions at once")
	}
	return nil
}
