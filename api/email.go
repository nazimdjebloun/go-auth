package api

import "time"

// EmailChangeActor identifies the authenticated account and initiating session.
// Transports must supply both from validated credentials, never JSON.
type EmailChangeActor struct {
	UserID    string `json:"-"`
	SessionID string `json:"-"`
}

// RequestEmailChangeInput starts confirmation of the current and new addresses.
type RequestEmailChangeInput struct {
	Actor    EmailChangeActor `json:"-"`
	NewEmail string           `json:"newEmail"`
	Password string           `json:"password"`
}

// EmailChangeResult identifies a pending request without exposing its proofs.
type EmailChangeResult struct {
	RequestID string    `json:"requestId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// ConfirmEmailChangeInput proves both mailboxes in the initiating session.
type ConfirmEmailChangeInput struct {
	Actor            EmailChangeActor `json:"-"`
	RequestID        string           `json:"requestId"`
	CurrentEmailCode string           `json:"currentEmailCode"`
	NewEmailCode     string           `json:"newEmailCode"`
}

// ResendEmailChangeInput rotates the current or new address's code.
type ResendEmailChangeInput struct {
	Actor       EmailChangeActor `json:"-"`
	RequestID   string           `json:"requestId"`
	Destination string           `json:"destination"`
}

// CancelEmailChangeInput cancels only the caller's named pending request.
type CancelEmailChangeInput struct {
	Actor     EmailChangeActor `json:"-"`
	RequestID string           `json:"requestId"`
}
