package port

import (
	"errors"
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
