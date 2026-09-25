package api

import (
	"github.com/nazimdjebloun/go-auth/domain"
)

// ListSessionsResult contains sessions and the matching total.
type ListSessionsResult struct {
	Sessions []domain.Session
}

// SessionResult bundles a session with the raw tokens issued alongside it.
// Only the hashes are ever persisted, so session creation and refresh are the
// only places raw SessionToken and RefreshToken values exist.
type SessionResult struct {
	Session      *domain.Session
	SessionToken string
	RefreshToken string
}
