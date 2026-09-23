// Package httproutes assembles the built-in HTTP handlers with their route-specific middleware.
package httproutes

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/internal/handler"
	"github.com/nazimdjebloun/go-auth/internal/routes"
)

// Entry pairs a canonical route pattern with its fully wrapped handler.
type Entry struct {
	Pattern string
	Handler http.Handler
}

// Features selects the route groups enabled by the validated configuration.
type Features struct {
	EmailRegistration bool
	Invite            bool
	OAuth             bool
	Organizations     bool
}

// Middleware contains the exact wrappers used by the built-in HTTP routes.
// The order in each Build entry is outermost to innermost.
type Middleware struct {
	CORS, RateLimit, CSRFToken, CSRF, Auth, Admin func(http.Handler) http.Handler
	OrgMember, OrgAdmin, OrgOwner                 func(http.Handler) http.Handler
}

// Build constructs the route registry used by Mount and Handler.
// Every entry has a canonical ServeMux pattern and its full middleware chain.
func Build(features Features, h *handler.Handler, oauthHandlers *handler.OAuthHandlers, mw Middleware) []Entry {
	corsMW, rateLimitMW := mw.CORS, mw.RateLimit
	csrfTokenMW, csrfMW := mw.CSRFToken, mw.CSRF
	authMW, adminMW := mw.Auth, mw.Admin
	orgMemberMW, orgAdminMW, orgOwnerMW := mw.OrgMember, mw.OrgAdmin, mw.OrgOwner

	// CORS remains outermost so preflight exits before rate limiting or auth.
	wrappedAdminListAuditLogs := corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListAuditLogs)))))
	wrappedAdminListUserAuditLogs := corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListUserAuditLogs)))))
	wrappedAdminListSessions := corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListSessions)))))
	entries := []Entry{
		{routes.Login, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.Login)))))},
		{routes.AdminLogin, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.AdminLogin)))))},
		{routes.ForgotPassword, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.ForgotPassword)))))},
		{routes.ResetPassword, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.ResetPassword)))))},
		{routes.VerifyEmail, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.VerifyEmail)))))},
		{routes.TwoFactorVerify, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.VerifyTwoFactor)))))},
		{routes.TwoFactorResend, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.ResendTwoFactor)))))},
		{routes.TwoFactorEnable, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.Enable2FA))))))},
		{routes.TwoFactorDisable, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.Disable2FA))))))},
		{routes.Logout, corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.Logout)))))},
		{routes.Me, corsMW(rateLimitMW(authMW(http.HandlerFunc(h.GetMe))))},
		{routes.CSRFToken, corsMW(csrfTokenMW(http.HandlerFunc(h.GetCSRFToken)))},
		{routes.ChangeName, corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ChangeName)))))},
		{routes.ListSessions, corsMW(authMW(http.HandlerFunc(h.ListSessions)))},
		{routes.AllSessions, corsMW(authMW(http.HandlerFunc(h.GetAllSessions)))},
		{routes.RevokeSession, corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RevokeSession)))))},
		{routes.RevokeManySessions, corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RevokeManySessions)))))},
		{routes.RevokeAllSessions, corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RevokeAllSessions)))))},
		{routes.ChangePassword, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ChangePassword))))))},
		{routes.SetPasswordRequest, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.SetPasswordRequest))))))},
		{routes.SetPasswordConfirm, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.SetPasswordConfirm)))))},
		{routes.DeleteAccount, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.DeleteAccount))))))},
		{routes.RequestDeleteAccount, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.RequestDeleteAccount))))))},
		{routes.ConfirmDeleteAccount, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ConfirmDeleteAccount))))))},
		{routes.ResendVerification, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ResendVerification))))))},
		{routes.ResendVerificationPublic, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.ResendVerificationPublic)))))},
		{routes.RefreshToken, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.RefreshToken)))))},
		{routes.ListUsers, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.ListUsers)))))},
		{routes.AdminCountUsers, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.CountUsers)))))},
		{routes.GetUserDetail, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.GetUserDetail)))))},
		{routes.UpdateUserRole, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.UpdateUserRole)))))))},
		{routes.BanUser, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BanUser)))))))},
		{routes.UnbanUser, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.UnbanUser)))))))},
		{routes.DeleteUser, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.DeleteUser)))))))},
		{routes.AdminCreateUser, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminCreateUser)))))))},
		{routes.AdminListUserSessions, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListUserSessions)))))},
		{routes.AdminRevokeUserSession, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminRevokeUserSession)))))))},
		{routes.RevokeUserSessions, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.RevokeUserSessions)))))))},
		{routes.AdminListAuditLogs, wrappedAdminListAuditLogs},
		{routes.AdminCountAuditLogs, wrappedAdminListAuditLogs},
		{routes.AdminListUserAuditLogs, wrappedAdminListUserAuditLogs},
		{routes.AdminCountUserAuditLogs, wrappedAdminListUserAuditLogs},
		{routes.AdminStats, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.GetAdminStats)))))},
		{routes.AdminRegistrationTrend, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.GetRegistrationTrend)))))},
		{routes.AdminLoginActivity, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.GetLoginActivity)))))},
		{routes.AdminListSessions, wrappedAdminListSessions},
		{routes.AdminCountSessions, wrappedAdminListSessions},
		{routes.BulkBanUsers, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkBanUsers)))))))},
		{routes.BulkUnbanUsers, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkUnbanUsers)))))))},
		{routes.BulkDeleteUsers, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkDeleteUsers)))))))},
		{routes.BulkRevokeUserSessions, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkRevokeUserSessions)))))))},
	}

	if features.EmailRegistration {
		entries = append(entries,
			Entry{routes.Register, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.Register)))))},
		)
	}

	if features.Invite {
		entries = append(entries,
			Entry{routes.InviteInfo, corsMW(rateLimitMW(http.HandlerFunc(h.GetInviteInfo)))},
			Entry{routes.InviteRegister, corsMW(rateLimitMW(csrfTokenMW(csrfMW(http.HandlerFunc(h.InviteRegister)))))},
			Entry{routes.CreateInvite, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.CreateInvite)))))))},
			Entry{routes.ListInvites, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.ListInvites)))))},
			Entry{routes.AdminCountInvites, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.CountInvites)))))},
			Entry{routes.RevokeInvite, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.RevokeInvite)))))))},
			Entry{routes.ResendInvite, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.ResendInvite)))))))},
			Entry{routes.HardDeleteInvite, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.HardDeleteInvite)))))))},
			Entry{routes.BulkSendInvites, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkSendInvites)))))))},
			Entry{routes.BulkResendInvites, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkResendInvites)))))))},
			Entry{routes.BulkRevokeInvites, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkRevokeInvites)))))))},
			Entry{routes.BulkDeleteInvites, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.BulkDeleteInvites)))))))},
		)
	}

	if features.OAuth {
		wrappedOAuthCallback := corsMW(rateLimitMW(http.HandlerFunc(oauthHandlers.Callback)))
		entries = append(entries,
			Entry{routes.OAuthInitiate, corsMW(rateLimitMW(http.HandlerFunc(oauthHandlers.Initiate)))},
			Entry{routes.OAuthCallbackGet, wrappedOAuthCallback},
			Entry{routes.OAuthCallbackPost, wrappedOAuthCallback},
			Entry{routes.OAuthLink, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(oauthHandlers.InitiateLink))))))},
			Entry{routes.OAuthUnlink, corsMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(oauthHandlers.Unlink)))))},
			Entry{routes.OAuthProviders, corsMW(authMW(http.HandlerFunc(oauthHandlers.ListConnected)))},
		)
	}

	if features.Organizations {
		wrappedAdminListOrgs := corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListOrgs)))))
		wrappedAdminListOrgMembers := corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListOrgMembers)))))
		wrappedAdminListUserOrgs := corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminListUserOrgs)))))
		entries = append(entries,
			Entry{routes.CreateOrg, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.CreateOrg))))))},
			Entry{routes.ListUserOrgs, corsMW(authMW(http.HandlerFunc(h.ListUserOrgs)))},
			Entry{routes.CountUserOrgs, corsMW(authMW(http.HandlerFunc(h.CountUserOrgs)))},
			Entry{routes.GetOrg, corsMW(rateLimitMW(authMW(orgMemberMW(http.HandlerFunc(h.GetOrg)))))},
			Entry{routes.UpdateOrg, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.UpdateOrg))))))))},
			Entry{routes.DeleteOrg, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgOwnerMW(http.HandlerFunc(h.DeleteOrg))))))))},
			Entry{routes.ListOrgMembers, corsMW(rateLimitMW(authMW(orgMemberMW(http.HandlerFunc(h.ListOrgMembers)))))},
			Entry{routes.CountOrgMembers, corsMW(authMW(orgMemberMW(http.HandlerFunc(h.CountOrgMembers))))},
			Entry{routes.RemoveOrgMember, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.RemoveMember))))))))},
			Entry{routes.UpdateOrgMemberRole, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.UpdateMemberRole))))))))},
			Entry{routes.AdminListOrgs, wrappedAdminListOrgs},
			Entry{routes.AdminCountOrgs, wrappedAdminListOrgs},
			Entry{routes.AdminGetOrg, corsMW(rateLimitMW(authMW(adminMW(http.HandlerFunc(h.AdminGetOrg)))))},
			Entry{routes.AdminListOrgMembers, wrappedAdminListOrgMembers},
			Entry{routes.AdminCountOrgMembers, wrappedAdminListOrgMembers},
			Entry{routes.AdminAddOrgMember, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminAddOrgMember)))))))},
			Entry{routes.AdminDeleteOrg, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminDeleteOrg)))))))},
			Entry{routes.AdminRemoveOrgMember, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminRemoveOrgMember)))))))},
			Entry{routes.AdminUpdateOrgMemberRole, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminUpdateOrgMemberRole)))))))},
			Entry{routes.AdminListUserOrgs, wrappedAdminListUserOrgs},
			Entry{routes.AdminCountUserOrgs, wrappedAdminListUserOrgs},
			Entry{routes.LeaveOrg, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(http.HandlerFunc(h.LeaveOrg)))))))},
			Entry{routes.SetActiveOrg, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.SetActiveOrg))))))},
			Entry{routes.ClearActiveOrg, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.ClearActiveOrg))))))},
			Entry{routes.CreateOrgInvite, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.CreateOrgInvite))))))))},
			Entry{routes.AcceptOrgInvite, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(http.HandlerFunc(h.AcceptOrgInvite))))))},
			Entry{routes.ListOrgInvites, corsMW(rateLimitMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.ListOrgInvites))))))},
			Entry{routes.CountOrgInvites, corsMW(rateLimitMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.CountOrgInvites))))))},
			Entry{routes.ResendOrgInvite, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.ResendOrgInvite))))))))},
			Entry{routes.DeleteOrgInvite, corsMW(rateLimitMW(csrfTokenMW(csrfMW(authMW(orgMemberMW(orgAdminMW(http.HandlerFunc(h.DeleteOrgInvite))))))))},
		)
	}

	return entries
}
