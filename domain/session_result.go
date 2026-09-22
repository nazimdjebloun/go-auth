package domain

// SessionResult bundles a session with the raw tokens issued alongside it.
// Only the hashes are ever persisted, so session creation and refresh are the
// only places raw SessionToken and RefreshToken values exist.
type SessionResult struct {
	Session      *Session
	SessionToken string
	RefreshToken string
}
