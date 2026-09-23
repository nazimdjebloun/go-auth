package port

import (
	"errors"
	"time"
)

// ErrDuplicateKey is returned by a repository's Create method when the
// underlying store rejects the write with a unique-constraint violation —
// e.g. two requests racing to register the same email, link the same
// provider account, or create the same org slug. It's a storage-outcome
// contract, not a sqlstore-specific detail, so it lives here rather than in
// sqlstore: service depends on port and domain only, and checking
// errors.Is(err, port.ErrDuplicateKey) lets it react to the race without
// importing sqlstore or knowing which driver produced the error. Callers
// translate it to the appropriate domain sentinel (domain.ErrEmailAlreadyExists,
// domain.ErrOrgSlugExists, domain.ErrProviderAccountExists, ...).
var ErrDuplicateKey = errors.New("port: duplicate key")

// DailyCount is one bucket of a day-by-day aggregate — the shape both
// UserRepository.CountByDay and AuditLogRepository.CountByDay return, for
// building a registrations-over-time chart or a GitHub-style login heatmap
// without pulling raw rows client-side.
type DailyCount struct {
	Date  time.Time `json:"date"` // truncated to day, UTC
	Count int       `json:"count"`
}
