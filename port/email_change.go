package port

import (
	"context"
	"time"
)

// EmailChangeRequest stores one account's current confirmation lineage and
// start budget. Only hashes of confirmation codes and credential state persist.
type EmailChangeRequest struct {
	UserID, ID, SessionID, Scope                 string
	CurrentEmail, NewEmail                       string
	CurrentCodeHash, NewCodeHash, IdentityHash   string
	Status                                       string
	CreatedAt, ExpiresAt, BudgetStartedAt        time.Time
	CurrentSentAt, NewSentAt                     time.Time
	Starts, Attempts, CurrentResends, NewResends int
}

// EmailChangeStore joins the caller's transaction. Load locks the request;
// Load/Save/ChangeAddress/InvalidateCredentials require the owning user lock.
type EmailChangeStore interface {
	Load(context.Context, string) (*EmailChangeRequest, error)
	Save(context.Context, *EmailChangeRequest) error
	ChangeAddress(context.Context, string, string, string, time.Time) (bool, error)
	InvalidateCredentials(context.Context, string) error
	DiscardVersion(context.Context, *EmailChangeRequest) error
}

// EmailChangeInvalidator cancels proofs inside a credential/settings transaction.
type EmailChangeInvalidator interface {
	CancelForUser(context.Context, string) error
}
