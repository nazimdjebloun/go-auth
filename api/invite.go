package api

import (
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// BulkInviteEmailsInput is the input for bulk send, which is keyed by address
// rather than by ID — the invites don't exist yet.
type BulkInviteEmailsInput struct {
	Emails  []string
	ActorID string
}

// BulkInviteFailure names the invite (by ID, or by email for a send) that
// didn't succeed, with the same stable code a single call would have returned.
type BulkInviteFailure struct {
	InviteID string `json:"inviteId,omitempty"`
	Email    string `json:"email,omitempty"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// BulkInviteIDsInput is the input for the ID-keyed bulk actions.
type BulkInviteIDsInput struct {
	InviteIDs []string
	ActorID   string
}

// BulkInviteResult reports per-item outcome, not overall success.
type BulkInviteResult struct {
	Succeeded []string            `json:"succeeded"`
	Failed    []BulkInviteFailure `json:"failed"`
}

// CompleteInviteInput contains values used to register from an invitation.
type CompleteInviteInput struct {
	Code            string
	Name            string
	Password        string
	ConfirmPassword string
	IP              string
	UserAgent       string
}

// CompleteInviteResult contains the registered user and session.
type CompleteInviteResult struct {
	User         *domain.User    `json:"user"`
	Session      *domain.Session `json:"session,omitempty"`
	SessionToken string          `json:"sessionToken,omitempty"`
	RefreshToken string          `json:"refreshToken,omitempty"`

	RequiresTwoFactor  bool      `json:"requiresTwoFactor,omitempty"`
	CodeSent           bool      `json:"codeSent,omitempty"`
	TwoFactorChallenge string    `json:"challengeId,omitempty"`
	TwoFactorExpiresAt time.Time `json:"twoFactorExpiresAt,omitempty"`

	bindingToken string // see RegisterResult.bindingToken
}

// BindingToken returns the challenge binding token for the handler to set as a
// cookie. Not serialized — see RegisterResult.bindingToken.
func (r *CompleteInviteResult) BindingToken() string { return r.bindingToken }

// CreateInviteInput contains values used to create an account invitation.
type CreateInviteInput struct {
	Email   string
	AdminID string
}

// ListInvitesInput contains account invitation filters.
type ListInvitesInput struct {
	ActorID        string
	Offset         int
	Limit          int
	Search         string
	Status         string
	OrderBy        InviteSortField
	OrderDirection SortDirection
}

// NewCompleteInviteResult attaches the challenge binding token without serializing it.
func NewCompleteInviteResult(result CompleteInviteResult, bindingToken string) *CompleteInviteResult {
	result.bindingToken = bindingToken
	return &result
}
