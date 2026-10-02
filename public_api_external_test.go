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
	_, _ = services.Org.CreateOrg(ctx, api.CreateOrgInput{})
	_, _ = services.Admin.ListUsers(ctx, api.AdminListUsersInput{OrderBy: api.UserSortCreatedAt})
	_ = api.SessionResult{}
	_ = api.AuditLogEntry{}
	_ = api.DailyCount{}
}
