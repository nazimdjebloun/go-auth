package goauth

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// GetActor validates a raw session credential for a custom backend transport and
// returns only user/session attribution. It applies GetSession's current user,
// session and email-verification checks. It does not refresh credentials, touch
// activity, authorize a business operation, or independently assert MFA
// assurance; permission checks retain their own current assurance policy.
// Do not persist the actor or accept these IDs in place of a credential.
func (a *Auth) GetActor(ctx context.Context, rawSessionToken string) (api.Actor, error) {
	user, session, err := a.GetSession(ctx, rawSessionToken)
	if err != nil {
		return api.Actor{}, err
	}
	if user == nil || session == nil || user.ID == "" || session.ID == "" || session.UserID != user.ID {
		return api.Actor{}, domain.ErrInternal
	}
	return api.Actor{UserID: user.ID, SessionID: session.ID}, nil
}

// AuthorizeOrg checks a current organization permission and returns its tenant
// scope. Unlike the lower-level permission service, this session-bound business
// boundary requires both user and session IDs. Supply them from trusted backend
// authentication, for example GetActor or middleware.ActorFromContext.
//
// Call this inside a business service before accessing tenant-owned data. An old
// OrgScope or role snapshot does not skip the live check. Include scope.OrgID in
// every repository query. Authorization and a later application write are separate
// operations; this method does not make them one transaction.
func (a *Auth) AuthorizeOrg(ctx context.Context, input api.CheckOrgPermissionInput) (OrgScope, error) {
	if a.services.OrgPermissions == nil {
		return OrgScope{}, domain.ErrOrgPermissionsDisabled
	}
	if input.Actor.UserID == "" || input.Actor.SessionID == "" {
		return OrgScope{}, domain.ErrOrgForbidden
	}
	decision, err := a.services.OrgPermissions.CheckPermission(ctx, input)
	if err != nil {
		return OrgScope{}, err
	}
	if decision == nil {
		return OrgScope{}, domain.ErrInternal
	}
	if !decision.Allowed {
		return OrgScope{}, domain.ErrOrgForbidden
	}
	if input.Actor.OrgID == "" || !decision.MembershipRole.IsValid() {
		return OrgScope{}, domain.ErrInternal
	}
	return OrgScope{
		OrgID:     input.Actor.OrgID,
		UserID:    input.Actor.UserID,
		SessionID: input.Actor.SessionID,
		Role:      decision.MembershipRole,
	}, nil
}
