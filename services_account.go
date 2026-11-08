package goauth

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// AccountServices binds self-service capabilities to one authenticated actor.
// Every call checks current session ownership, liveness and account access.
// Optional OAuth/organization capabilities are nil when disabled. Holding this
// value does not authenticate a client or preserve access after revocation.
type AccountServices struct {
	Profile   AccountProfileOperations
	Session   AccountSessionOperations
	Password  AccountPasswordOperations
	Verify    AccountVerificationOperations
	TwoFactor AccountTwoFactorOperations
	OAuth     AccountOAuthOperations
	Org       AccountOrgOperations
	OrgInvite AccountOrgInviteOperations
}

// AccountProfileOperations acts only on the bound account; proofs remain required.
type AccountProfileOperations interface {
	ChangeName(context.Context, string) error
	DeleteAccount(context.Context, string) error
	RequestDeleteAccount(context.Context) error
	ConfirmDeleteAccount(context.Context, string) error
}

// AccountSessionOperations cannot issue credentials or target another account.
type AccountSessionOperations interface {
	Logout(context.Context) error
	List(context.Context, api.SessionPageInput) ([]domain.Session, int, error)
	ListAll(context.Context) ([]domain.Session, error)
	RevokeByID(context.Context, string) (bool, error)
	RevokeMany(context.Context, []string) (int, error)
	RevokeOthers(context.Context) error
	RevokeAll(context.Context) error
}

// AccountPasswordOperations retains password/code proof and credential transactions.
type AccountPasswordOperations interface {
	ChangePassword(context.Context, api.ChangeOwnPasswordInput) error
	RequestSetPassword(context.Context) error
	ConfirmSetPassword(context.Context, api.ConfirmOwnSetPasswordInput) error
}

// AccountVerificationOperations permits resend for a live unverified account too.
type AccountVerificationOperations interface {
	ResendVerification(context.Context) (*api.VerificationResult, error)
}

// AccountTwoFactorOperations changes preferences using existing password/code proof.
// It cannot start an unauthenticated login challenge or issue a session directly.
type AccountTwoFactorOperations interface {
	RequestSettingsChallenge(context.Context, string) (*api.ChallengeResult, error)
	Enable(context.Context, api.EnableOwnTwoFactorInput) error
	Disable(context.Context, api.DisableOwnTwoFactorInput) error
}

// AccountOAuthOperations binds linking/removal to the authenticated account/session.
type AccountOAuthOperations interface {
	InitiateLink(context.Context, string) (*api.OAuthInitiation, error)
	Unlink(context.Context, string) error
	ListConnected(context.Context) ([]domain.ProviderAccount, error)
}

// AccountOrgOperations derives all user/session attribution from the bound actor.
type AccountOrgOperations interface {
	CreateOrg(context.Context, api.CreateOwnOrgInput) (*domain.Organization, error)
	ListUserOrgs(context.Context, api.ListOwnOrgsInput) (*api.ListUserOrgsResult, error)
	CountUserOrgs(context.Context, api.ListOwnOrgsInput) (int, error)
	LeaveOrg(context.Context, string) error
	SetActiveOrg(context.Context, string) error
	ClearActiveOrg(context.Context) error
}

// AccountOrgInviteOperations accepts email-bound invitations as the bound user.
type AccountOrgInviteOperations interface {
	AcceptInvite(context.Context, string) error
}

// Account binds self-service to attribution from GetActor or authenticated HTTP
// context. Never construct that attribution from client user/session IDs. Each
// operation revalidates it, so a retained handle cannot bypass session revocation.
// Credential proofs and action-specific policies remain in the existing services.
func (a *Auth) Account(actor api.Actor) AccountServices {
	b := accountBinding{auth: a, actor: actor}
	s := AccountServices{
		Profile: accountProfile{b}, Session: accountSession{b}, Password: accountPassword{b},
		Verify: accountVerification{b}, TwoFactor: accountTwoFactor{b},
	}
	if a.services.OAuth != nil {
		s.OAuth = accountOAuth{b}
	}
	if a.services.Org != nil {
		s.Org = accountOrg{b}
	}
	if a.services.OrgInvite != nil {
		s.OrgInvite = accountOrgInvite{b}
	}
	return s
}

type accountBinding struct {
	auth  *Auth
	actor api.Actor
}

func (b accountBinding) check(ctx context.Context) (*domain.User, *domain.Session, error) {
	return b.auth.services.Auth.ValidateAccountActor(ctx, b.actor)
}

type accountProfile struct{ bound accountBinding }
type accountSession struct{ bound accountBinding }
type accountPassword struct{ bound accountBinding }
type accountVerification struct{ bound accountBinding }
type accountTwoFactor struct{ bound accountBinding }
type accountOAuth struct{ bound accountBinding }
type accountOrg struct{ bound accountBinding }
type accountOrgInvite struct{ bound accountBinding }

func (s accountProfile) ChangeName(ctx context.Context, name string) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Auth.ChangeName(ctx, api.ChangeNameInput{UserID: s.bound.actor.UserID, Name: name})
}

func (s accountProfile) DeleteAccount(ctx context.Context, password string) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Auth.DeleteAccount(
		ctx,
		api.DeleteAccountInput{
			UserID:   s.bound.actor.UserID,
			Password: password,
		},
	)
}

func (s accountProfile) RequestDeleteAccount(ctx context.Context) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Auth.RequestDeleteAccount(ctx, s.bound.actor.UserID)
}

func (s accountProfile) ConfirmDeleteAccount(ctx context.Context, code string) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Auth.ConfirmDeleteAccount(
		ctx,
		api.ConfirmDeleteAccountInput{
			UserID: s.bound.actor.UserID,
			Code:   code,
		},
	)
}

func (s accountSession) Logout(ctx context.Context) error {
	if _, _, err := s.bound.auth.services.Auth.ValidateAccountIdentity(ctx, s.bound.actor); err != nil {
		return err
	}
	return s.bound.auth.services.Auth.Logout(ctx, s.bound.actor.SessionID)
}

func (s accountSession) List(ctx context.Context, input api.SessionPageInput) ([]domain.Session, int, error) {
	if _, _, err := s.bound.check(ctx); err != nil {
		return nil, 0, err
	}
	return s.bound.auth.services.Session.List(
		ctx,
		api.ListSessionsInput{
			UserID: s.bound.actor.UserID,
			Offset: input.Offset,
			Limit:  input.Limit,
		},
	)
}

func (s accountSession) ListAll(ctx context.Context) ([]domain.Session, error) {
	if _, _, err := s.bound.check(ctx); err != nil {
		return nil, err
	}
	return s.bound.auth.services.Session.ListAll(ctx, s.bound.actor.UserID)
}

func (s accountSession) RevokeByID(ctx context.Context, sessionID string) (bool, error) {
	if _, _, err := s.bound.check(ctx); err != nil {
		return false, err
	}
	return s.bound.auth.services.Session.RevokeByIDForUser(
		ctx,
		api.RevokeSessionForUserInput{
			UserID:    s.bound.actor.UserID,
			SessionID: sessionID,
		},
	)
}

func (s accountSession) RevokeMany(ctx context.Context, sessionIDs []string) (int, error) {
	if _, _, err := s.bound.check(ctx); err != nil {
		return 0, err
	}
	return s.bound.auth.services.Session.RevokeManyForUser(
		ctx,
		api.RevokeSessionsForUserInput{
			UserID:     s.bound.actor.UserID,
			SessionIDs: sessionIDs,
		},
	)
}

func (s accountSession) RevokeOthers(ctx context.Context) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Session.RevokeAllExcept(
		ctx,
		api.RevokeAllSessionsExceptInput{
			UserID:          s.bound.actor.UserID,
			ExceptSessionID: s.bound.actor.SessionID,
		},
	)
}

func (s accountSession) RevokeAll(ctx context.Context) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Session.RevokeAll(ctx, s.bound.actor.UserID)
}

func (s accountPassword) ChangePassword(ctx context.Context, input api.ChangeOwnPasswordInput) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Password.ChangePassword(
		ctx,
		api.ChangePasswordInput{
			UserID:          s.bound.actor.UserID,
			ExceptSessionID: s.bound.actor.SessionID,
			OldPassword:     input.OldPassword,
			NewPassword:     input.NewPassword,
		},
	)
}

func (s accountPassword) RequestSetPassword(ctx context.Context) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Password.RequestSetPassword(ctx, s.bound.actor.UserID)
}

func (s accountPassword) ConfirmSetPassword(ctx context.Context, input api.ConfirmOwnSetPasswordInput) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Password.ConfirmSetPassword(
		ctx,
		api.ConfirmSetPasswordInput{
			UserID:      s.bound.actor.UserID,
			Code:        input.Code,
			NewPassword: input.NewPassword,
		},
	)
}

func (s accountVerification) ResendVerification(ctx context.Context) (*api.VerificationResult, error) {
	if _, _, err := s.bound.auth.services.Auth.ValidateAccountIdentity(ctx, s.bound.actor); err != nil {
		return nil, err
	}
	return s.bound.auth.services.Verify.ResendVerification(ctx, s.bound.actor.UserID)
}

func (s accountTwoFactor) RequestSettingsChallenge(ctx context.Context, action string) (*api.ChallengeResult, error) {
	if _, _, err := s.bound.check(ctx); err != nil {
		return nil, err
	}
	return s.bound.auth.services.TwoFactor.RequestSettingsChallenge(
		ctx,
		api.TwoFactorSettingsChallengeInput{
			UserID:          s.bound.actor.UserID,
			CallerSessionID: s.bound.actor.SessionID,
			Action:          action,
		},
	)
}

func (s accountTwoFactor) Enable(ctx context.Context, input api.EnableOwnTwoFactorInput) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.TwoFactor.Enable(
		ctx,
		api.TwoFactorEnableInput{
			UserID:            s.bound.actor.UserID,
			CallerSessionID:   s.bound.actor.SessionID,
			Password:          input.Password,
			ChallengeID:       input.ChallengeID,
			Code:              input.Code,
			KeepOtherSessions: input.KeepOtherSessions,
		},
	)
}

func (s accountTwoFactor) Disable(ctx context.Context, input api.DisableOwnTwoFactorInput) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.TwoFactor.Disable(
		ctx,
		api.TwoFactorDisableInput{
			UserID:          s.bound.actor.UserID,
			CallerSessionID: s.bound.actor.SessionID,
			Password:        input.Password,
			ChallengeID:     input.ChallengeID,
			Code:            input.Code,
		},
	)
}

func (s accountOAuth) InitiateLink(ctx context.Context, provider string) (*api.OAuthInitiation, error) {
	_, session, err := s.bound.check(ctx)
	if err != nil {
		return nil, err
	}
	return s.bound.auth.services.OAuth.InitiateLink(
		ctx,
		api.OAuthLinkInput{
			UserID:           s.bound.actor.UserID,
			SessionTokenHash: session.TokenHash,
			Provider:         provider,
		},
	)
}

func (s accountOAuth) Unlink(ctx context.Context, provider string) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.OAuth.Unlink(ctx, api.OAuthUnlinkInput{UserID: s.bound.actor.UserID, Provider: provider})
}

func (s accountOAuth) ListConnected(ctx context.Context) ([]domain.ProviderAccount, error) {
	if _, _, err := s.bound.check(ctx); err != nil {
		return nil, err
	}
	return s.bound.auth.services.OAuth.ListConnected(ctx, s.bound.actor.UserID)
}

func (s accountOrg) CreateOrg(ctx context.Context, input api.CreateOwnOrgInput) (*domain.Organization, error) {
	if _, _, err := s.bound.check(ctx); err != nil {
		return nil, err
	}
	return s.bound.auth.services.Org.CreateOrg(
		ctx,
		api.CreateOrgInput{
			OwnerID: s.bound.actor.UserID,
			Name:    input.Name,
			Slug:    input.Slug,
		},
	)
}

func (s accountOrg) listInput(input api.ListOwnOrgsInput) api.ListUserOrgsInput {
	return api.ListUserOrgsInput{
		UserID:         s.bound.actor.UserID,
		ActorSessionID: s.bound.actor.SessionID,
		Search:         input.Search,
		Role:           input.Role,
		OrderBy:        input.OrderBy,
		OrderDirection: input.OrderDirection,
		Offset:         input.Offset,
		Limit:          input.Limit,
	}
}

func (s accountOrg) ListUserOrgs(ctx context.Context, input api.ListOwnOrgsInput) (*api.ListUserOrgsResult, error) {
	if _, _, err := s.bound.check(ctx); err != nil {
		return nil, err
	}
	return s.bound.auth.services.Org.ListUserOrgs(ctx, s.listInput(input))
}

func (s accountOrg) CountUserOrgs(ctx context.Context, input api.ListOwnOrgsInput) (int, error) {
	if _, _, err := s.bound.check(ctx); err != nil {
		return 0, err
	}
	return s.bound.auth.services.Org.CountUserOrgs(ctx, s.listInput(input))
}

func (s accountOrg) LeaveOrg(ctx context.Context, orgID string) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Org.LeaveOrg(ctx, api.LeaveOrgInput{UserID: s.bound.actor.UserID, OrgID: orgID})
}

func (s accountOrg) SetActiveOrg(ctx context.Context, orgID string) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Org.SetActiveOrg(
		ctx,
		api.SetActiveOrgInput{
			UserID:    s.bound.actor.UserID,
			SessionID: s.bound.actor.SessionID,
			OrgID:     orgID,
		},
	)
}

func (s accountOrg) ClearActiveOrg(ctx context.Context) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.Org.ClearActiveOrg(ctx, api.ClearActiveOrgInput{SessionID: s.bound.actor.SessionID})
}

func (s accountOrgInvite) AcceptInvite(ctx context.Context, code string) error {
	if _, _, err := s.bound.check(ctx); err != nil {
		return err
	}
	return s.bound.auth.services.OrgInvite.AcceptInvite(
		ctx,
		api.AcceptInviteInput{
			UserID:  s.bound.actor.UserID,
			RawCode: code,
		},
	)
}
