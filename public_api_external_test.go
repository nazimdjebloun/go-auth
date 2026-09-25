package goauth_test

import (
	"context"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/api"
)

// This compiles the public type surface from outside package goauth.
func publicTypesCompile(a *goauth.Auth, ctx context.Context) {
	services := a.Services()
	var _ goauth.AuthOperations = services.Auth
	var _ goauth.PasswordOperations = services.Password
	var _ goauth.SessionOperations = services.Session
	var _ goauth.VerifyOperations = services.Verify
	var _ goauth.InviteOperations = services.Invite
	var _ goauth.AdminOperations = services.Admin
	var _ goauth.OAuthOperations = services.OAuth
	var _ goauth.OrgOperations = services.Org
	var _ goauth.OrgInviteOperations = services.OrgInvite
	var _ goauth.TwoFactorOperations = services.TwoFactor
	_, _ = a.Login(ctx, api.LoginInput{})
	_, _ = services.Org.CreateOrg(ctx, api.CreateOrgInput{})
	_, _ = services.Admin.ListUsers(ctx, api.AdminListUsersInput{OrderBy: api.UserSortCreatedAt})
	_ = api.SessionResult{}
	_ = api.AuditLogEntry{}
	_ = api.DailyCount{}
}
