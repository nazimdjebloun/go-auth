package goauth

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// RequestEmailChange starts dual-mailbox confirmation in the actor's session.
func (a *Auth) RequestEmailChange(ctx context.Context, input api.RequestEmailChangeInput) (*api.EmailChangeResult, error) {
	if a.services.Email == nil {
		return nil, domain.ErrEmailChangeDisabled
	}
	return a.services.Email.RequestEmailChange(ctx, input)
}

// ConfirmEmailChange changes the address and revokes all existing sessions.
func (a *Auth) ConfirmEmailChange(ctx context.Context, input api.ConfirmEmailChangeInput) error {
	if a.services.Email == nil {
		return domain.ErrEmailChangeDisabled
	}
	return a.services.Email.ConfirmEmailChange(ctx, input)
}

// ResendEmailChange rotates one mailbox's code without extending the request.
func (a *Auth) ResendEmailChange(ctx context.Context, input api.ResendEmailChangeInput) (*api.EmailChangeResult, error) {
	if a.services.Email == nil {
		return nil, domain.ErrEmailChangeDisabled
	}
	return a.services.Email.ResendEmailChange(ctx, input)
}

// CancelEmailChange cancels only the named request in the initiating session.
func (a *Auth) CancelEmailChange(ctx context.Context, input api.CancelEmailChangeInput) error {
	if a.services.Email == nil {
		return domain.ErrEmailChangeDisabled
	}
	return a.services.Email.CancelEmailChange(ctx, input)
}
