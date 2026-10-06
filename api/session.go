package api

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// CreateSessionInput identifies the user and trusted client metadata for a session.
type CreateSessionInput struct {
	UserID    string `json:"-"`
	IP        string `json:"-"`
	UserAgent string `json:"-"`
}

// TouchSessionInput carries the access token and last activity observed during validation.
type TouchSessionInput struct {
	Token        string    `json:"-"`
	LastActiveAt time.Time `json:"-"`
}

// RevokeSessionForUserInput identifies a session and its authenticated owner.
type RevokeSessionForUserInput struct {
	SessionID string `json:"sessionId"`
	UserID    string `json:"-"`
}

// RevokeSessionsForUserInput identifies sessions and their authenticated owner.
type RevokeSessionsForUserInput struct {
	SessionIDs []string `json:"sessionIds"`
	UserID     string   `json:"-"`
}

// RevokeAllSessionsExceptInput retains one session while revoking the user's others.
type RevokeAllSessionsExceptInput struct {
	UserID          string `json:"-"`
	ExceptSessionID string `json:"exceptSessionId"`
}

// ListSessionsInput selects a page of the authenticated user's sessions.
type ListSessionsInput struct {
	UserID string `json:"-"`
	Offset int    `json:"offset"`
	Limit  int    `json:"limit"`
}

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
