package goauth_test

import (
	"context"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/api"
)

// This compiles the public type surface from outside package goauth.
func publicTypesCompile(ctx context.Context, a *goauth.Auth) {
	services := a.Services()
	_ = struct {
		Auth      goauth.AuthOperations
		Password  goauth.PasswordOperations
		Session   goauth.SessionOperations
		Verify    goauth.VerifyOperations
		Invite    goauth.InviteOperations
		Admin     goauth.AdminOperations
		OAuth     goauth.OAuthOperations
		Org       goauth.OrgOperations
		OrgInvite goauth.OrgInviteOperations
		TwoFactor goauth.TwoFactorOperations
	}{
		Auth:      services.Auth,
		Password:  services.Password,
		Session:   services.Session,
		Verify:    services.Verify,
		Invite:    services.Invite,
		Admin:     services.Admin,
		OAuth:     services.OAuth,
		Org:       services.Org,
		OrgInvite: services.OrgInvite,
		TwoFactor: services.TwoFactor,
	}
	_, _ = a.Login(ctx, api.LoginInput{})
	_ = services.Auth.ChangeName(ctx, api.ChangeNameInput{UserID: "user", Name: "New name"})
	_ = services.Auth.DeleteAccount(ctx, api.DeleteAccountInput{UserID: "user", Password: "password"})
	_, _ = services.Session.Create(ctx, api.CreateSessionInput{UserID: "user", IP: "127.0.0.1", UserAgent: "client"})
	_ = services.Session.Touch(ctx, api.TouchSessionInput{Token: "session-token"})
	_, _ = services.Session.RevokeByIDForUser(ctx, api.RevokeSessionForUserInput{SessionID: "session", UserID: "user"})
	_, _ = services.Session.RevokeManyForUser(ctx, api.RevokeSessionsForUserInput{SessionIDs: []string{"session"}, UserID: "user"})
	_ = services.Session.RevokeAllExcept(ctx, api.RevokeAllSessionsExceptInput{UserID: "user", ExceptSessionID: "session"})
	_, _, _ = services.Session.List(ctx, api.ListSessionsInput{UserID: "user", Offset: 0, Limit: 10})
	_, _ = services.OAuth.InitiateLink(ctx, api.OAuthLinkInput{
		Provider: "provider", UserID: "user", SessionTokenHash: "session-hash",
	})
	_, _ = services.OAuth.Callback(ctx, api.OAuthCallbackInput{
		Provider: "provider", Code: "code", State: "state", BrowserState: "cookie-state",
		SessionToken: "session-token", IP: "127.0.0.1", UserAgent: "client",
	})
	_ = services.OAuth.Unlink(ctx, api.OAuthUnlinkInput{UserID: "user", Provider: "provider"})
	_, _ = services.TwoFactor.Verify(ctx, api.TwoFactorVerifyInput{
		ChallengeID: "challenge", BindingToken: "binding", Code: "123456", IP: "127.0.0.1", UserAgent: "client",
	})
	_, _ = services.TwoFactor.Resend(ctx, api.TwoFactorResendInput{ChallengeID: "challenge", BindingToken: "binding"})
	_ = services.TwoFactor.Enable(ctx, api.TwoFactorEnableInput{
		UserID: "user", Password: "password", KeepOtherSessions: false, CallerSessionID: "session",
	})
	_ = services.TwoFactor.Disable(ctx, api.TwoFactorDisableInput{UserID: "user", Password: "password"})
	_ = services.Invite.HardDeleteInvite(ctx, api.HardDeleteInviteInput{InviteID: "invite", ActorID: "admin"})
	_ = services.Invite.RevokeInvite(ctx, api.RevokeInviteInput{InviteID: "invite", ActorID: "admin"})
	_ = services.Invite.ResendInviteEmail(ctx, api.ResendInviteEmailInput{InviteID: "invite", ActorID: "admin"})
	_ = services.OrgInvite.DeleteOrgInvite(ctx, api.DeleteOrgInviteInput{OrgID: "org", InviteID: "invite", ActorID: "actor"})
	_ = services.OrgInvite.ResendOrgInviteEmail(ctx, api.ResendOrgInviteEmailInput{
		OrgID: "org", InviteID: "invite", ActorID: "actor",
	})
	_, _ = services.Org.CreateOrg(ctx, api.CreateOrgInput{})
	_, _ = services.Admin.ListUsers(ctx, api.AdminListUsersInput{OrderBy: api.UserSortCreatedAt})
	_ = api.SessionResult{}
	_ = api.AuditLogEntry{}
	_ = api.DailyCount{}
}
