package goauth

import (
	"net/http"
	"strings"

	"github.com/nazimdjebloun/go-auth/internal/routes"
)

// routeEntry pairs a canonical route pattern (from internal/routes) with
// the already-middleware-wrapped handler that serves it.
type routeEntry struct {
	pattern string
	handler http.Handler
}

// Mount registers every enabled route onto mux. It requires a real
// *http.ServeMux (Go 1.22+'s pattern syntax, e.g. "GET /admin/users/{id}")
// because route handlers read path parameters with r.PathValue, which only
// ServeMux populates — mounting the same handlers on chi, gin, echo, or any
// router that doesn't call r.SetPathValue itself will 404 or read an empty
// ID on every parameterized route, with no error at mount time. Bridge to
// another router by having it populate PathValue before calling into these
// handlers, or use Auth.RequireAuth/RequireAdmin/RequireOrg plus
// auth.Services.* directly and write your own routing layer.
func (a *Auth) Mount(mux *http.ServeMux) {
	// All middleware (CORS, rate limit, csrf token, origin check, auth, admin)
	// is already baked into a.Handlers — CORS outermost so preflight OPTIONS
	// short-circuits before rate limiting. Mount only registers routes; do NOT
	// wrap the mux again with a.CORS or any other middleware.
	//
	// handle registers a route and, when CORS origins are configured, also the
	// exact OPTIONS twin for the same path. OPTIONS is registered 1:1 with each
	// route go-auth owns — never a catch-all — so preflight requests for paths
	// go-auth does not own (including a consumer's own routes on a shared mux)
	// still get a normal 404/405 and never reach the CORS layer.
	preflight := len(a.cfg.security.AllowedOrigins) > 0
	preflightPaths := make(map[string]bool)
	handle := func(pattern string, h http.Handler) {
		mux.Handle(pattern, h)
		if preflight {
			// OPTIONS is registered once per path. Multiple methods may share a
			// path (GET /auth/sessions, DELETE /auth/sessions), but preflight is
			// method-agnostic, so a duplicate registration would panic. CORS
			// short-circuits OPTIONS with 204 before the handler runs, so any
			// of the shared handlers answers it correctly.
			if i := strings.IndexByte(pattern, ' '); i > 0 {
				p := pattern[i+1:]
				if !preflightPaths[p] {
					preflightPaths[p] = true
					mux.Handle("OPTIONS "+p, h)
				}
			}
		}
	}

	entries := []routeEntry{
		{routes.Login, a.Handlers.Login},
		{routes.AdminLogin, a.Handlers.AdminLogin},
		{routes.ForgotPassword, a.Handlers.ForgotPassword},
		{routes.ResetPassword, a.Handlers.ResetPassword},
		{routes.VerifyEmail, a.Handlers.VerifyEmail},
		{routes.TwoFactorVerify, a.Handlers.VerifyTwoFactor},
		{routes.TwoFactorResend, a.Handlers.ResendTwoFactor},
		{routes.TwoFactorEnable, a.Handlers.Enable2FA},
		{routes.TwoFactorDisable, a.Handlers.Disable2FA},
		{routes.Logout, a.Handlers.Logout},
		{routes.Me, a.Handlers.GetMe},
		{routes.CSRFToken, a.Handlers.CSRFToken},
		{routes.ChangeName, a.Handlers.ChangeName},
		{routes.ListSessions, a.Handlers.ListSessions},
		{routes.AllSessions, a.Handlers.GetAllSessions},
		{routes.RevokeSession, a.Handlers.RevokeSession},
		{routes.RevokeManySessions, a.Handlers.RevokeManySessions},
		{routes.RevokeAllSessions, a.Handlers.RevokeAllSessions},
		{routes.ChangePassword, a.Handlers.ChangePassword},
		{routes.SetPasswordRequest, a.Handlers.SetPasswordRequest},
		{routes.SetPasswordConfirm, a.Handlers.SetPasswordConfirm},
		{routes.DeleteAccount, a.Handlers.DeleteAccount},
		{routes.RequestDeleteAccount, a.Handlers.RequestDeleteAccount},
		{routes.ConfirmDeleteAccount, a.Handlers.ConfirmDeleteAccount},
		{routes.ResendVerification, a.Handlers.ResendVerification},
		{routes.ResendVerificationPublic, a.Handlers.ResendVerificationPublic},
		{routes.RefreshToken, a.Handlers.RefreshToken},
		{routes.ListUsers, a.Handlers.ListUsers},
		{routes.AdminCountUsers, a.Handlers.CountUsers},
		{routes.GetUserDetail, a.Handlers.GetUserDetail},
		{routes.UpdateUserRole, a.Handlers.UpdateUserRole},
		{routes.BanUser, a.Handlers.BanUser},
		{routes.UnbanUser, a.Handlers.UnbanUser},
		{routes.DeleteUser, a.Handlers.DeleteUser},
		{routes.AdminCreateUser, a.Handlers.AdminCreateUser},
		{routes.AdminListUserSessions, a.Handlers.AdminListUserSessions},
		{routes.AdminRevokeUserSession, a.Handlers.AdminRevokeUserSession},
		{routes.RevokeUserSessions, a.Handlers.RevokeUserSessions},
		{routes.AdminListAuditLogs, a.Handlers.AdminListAuditLogs},
		{routes.AdminCountAuditLogs, a.Handlers.AdminListAuditLogs},
		{routes.AdminListUserAuditLogs, a.Handlers.AdminListUserAuditLogs},
		{routes.AdminCountUserAuditLogs, a.Handlers.AdminListUserAuditLogs},
		{routes.AdminStats, a.Handlers.AdminStats},
		{routes.AdminRegistrationTrend, a.Handlers.AdminRegistrationTrend},
		{routes.AdminLoginActivity, a.Handlers.AdminLoginActivity},
		{routes.AdminListSessions, a.Handlers.AdminListSessions},
		{routes.AdminCountSessions, a.Handlers.AdminListSessions},
		{routes.BulkBanUsers, a.Handlers.BulkBanUsers},
		{routes.BulkUnbanUsers, a.Handlers.BulkUnbanUsers},
		{routes.BulkDeleteUsers, a.Handlers.BulkDeleteUsers},
		{routes.BulkRevokeUserSessions, a.Handlers.BulkRevokeUserSessions},
	}

	if a.cfg.registration.EnableEmailPassword {
		entries = append(entries, routeEntry{routes.Register, a.Handlers.Register})
	}
	if a.cfg.registration.EnableInvite {
		entries = append(entries,
			routeEntry{routes.InviteInfo, a.Handlers.GetInviteInfo},
			routeEntry{routes.InviteRegister, a.Handlers.InviteRegister},
			routeEntry{routes.CreateInvite, a.Handlers.CreateInvite},
			routeEntry{routes.ListInvites, a.Handlers.ListInvites},
			routeEntry{routes.AdminCountInvites, a.Handlers.CountInvites},
			routeEntry{routes.RevokeInvite, a.Handlers.RevokeInvite},
			routeEntry{routes.ResendInvite, a.Handlers.ResendInvite},
			routeEntry{routes.HardDeleteInvite, a.Handlers.HardDeleteInvite},
			routeEntry{routes.BulkSendInvites, a.Handlers.BulkSendInvites},
			routeEntry{routes.BulkResendInvites, a.Handlers.BulkResendInvites},
			routeEntry{routes.BulkRevokeInvites, a.Handlers.BulkRevokeInvites},
			routeEntry{routes.BulkDeleteInvites, a.Handlers.BulkDeleteInvites},
		)
	}
	if a.cfg.registration.EnableOAuth && a.oAuthService != nil {
		entries = append(entries,
			routeEntry{routes.OAuthInitiate, a.Handlers.OAuthInitiate},
			routeEntry{routes.OAuthCallbackGet, a.Handlers.OAuthCallback},
			routeEntry{routes.OAuthCallbackPost, a.Handlers.OAuthCallback},
			routeEntry{routes.OAuthLink, a.Handlers.OAuthLink},
			routeEntry{routes.OAuthUnlink, a.Handlers.OAuthUnlink},
			routeEntry{routes.OAuthProviders, a.Handlers.OAuthProviders},
		)
	}
	if a.orgService != nil {
		entries = append(entries,
			routeEntry{routes.CreateOrg, a.Handlers.CreateOrg},
			routeEntry{routes.ListUserOrgs, a.Handlers.ListUserOrgs},
			routeEntry{routes.CountUserOrgs, a.Handlers.CountUserOrgs},
			routeEntry{routes.GetOrg, a.Handlers.GetOrg},
			routeEntry{routes.UpdateOrg, a.Handlers.UpdateOrg},
			routeEntry{routes.DeleteOrg, a.Handlers.DeleteOrg},
			routeEntry{routes.ListOrgMembers, a.Handlers.ListOrgMembers},
			routeEntry{routes.CountOrgMembers, a.Handlers.CountOrgMembers},
			routeEntry{routes.RemoveOrgMember, a.Handlers.RemoveOrgMember},
			routeEntry{routes.UpdateOrgMemberRole, a.Handlers.UpdateOrgMemberRole},
			routeEntry{routes.AdminListOrgs, a.Handlers.AdminListOrgs},
			routeEntry{routes.AdminCountOrgs, a.Handlers.AdminListOrgs},
			routeEntry{routes.AdminGetOrg, a.Handlers.AdminGetOrg},
			routeEntry{routes.AdminListOrgMembers, a.Handlers.AdminListOrgMembers},
			routeEntry{routes.AdminCountOrgMembers, a.Handlers.AdminListOrgMembers},
			routeEntry{routes.AdminAddOrgMember, a.Handlers.AdminAddOrgMember},
			routeEntry{routes.AdminDeleteOrg, a.Handlers.AdminDeleteOrg},
			routeEntry{routes.AdminRemoveOrgMember, a.Handlers.AdminRemoveOrgMember},
			routeEntry{routes.AdminUpdateOrgMemberRole, a.Handlers.AdminUpdateOrgMemberRole},
			routeEntry{routes.AdminListUserOrgs, a.Handlers.AdminListUserOrgs},
			routeEntry{routes.AdminCountUserOrgs, a.Handlers.AdminListUserOrgs},
			routeEntry{routes.LeaveOrg, a.Handlers.LeaveOrg},
			routeEntry{routes.SetActiveOrg, a.Handlers.SetActiveOrg},
			routeEntry{routes.ClearActiveOrg, a.Handlers.ClearActiveOrg},
			routeEntry{routes.CreateOrgInvite, a.Handlers.CreateOrgInvite},
			routeEntry{routes.AcceptOrgInvite, a.Handlers.AcceptOrgInvite},
			routeEntry{routes.ListOrgInvites, a.Handlers.ListOrgInvites},
			routeEntry{routes.CountOrgInvites, a.Handlers.CountOrgInvites},
			routeEntry{routes.ResendOrgInvite, a.Handlers.ResendOrgInvite},
			routeEntry{routes.DeleteOrgInvite, a.Handlers.DeleteOrgInvite},
		)
	}

	for _, e := range entries {
		handle(e.pattern, e.handler)
	}
}
