// Package routes is the single source of truth for every HTTP route
// go-auth mounts: the canonical "METHOD /path" string used to register it
// on a ServeMux, and everything derived from that path (the rate-limit
// table's glob form). It imports nothing else in this module, so anything
// is free to depend on it without risking an import cycle.
package routes

import "strings"

const (
	Register       = "POST /auth/register"
	Login          = "POST /auth/login"
	AdminLogin     = "POST /auth/admin/login"
	Logout         = "POST /auth/logout"
	ForgotPassword = "POST /auth/forgot-password"
	ResetPassword  = "POST /auth/reset-password"
	ChangePassword = "POST /auth/change-password"

	SetPasswordRequest = "POST /auth/set-password/request"
	SetPasswordConfirm = "POST /auth/set-password/confirm"

	VerifyEmail              = "POST /auth/verify-email"
	ResendVerification       = "POST /auth/resend-verification"
	ResendVerificationPublic = "POST /auth/verify-email/resend"

	Me           = "GET /auth/me"
	CheckSession = "GET /auth/check"
	CSRFToken    = "GET /auth/csrf-token"
	ChangeName   = "PUT /auth/name"

	ListSessions       = "GET /auth/sessions"
	AllSessions        = "GET /auth/sessions/all"
	RevokeSession      = "DELETE /auth/sessions/{id}"
	RevokeManySessions = "POST /auth/sessions/revoke"
	RevokeAllSessions  = "DELETE /auth/sessions"
	RefreshToken       = "POST /auth/refresh"

	DeleteAccount        = "DELETE /auth/account"
	RequestDeleteAccount = "POST /auth/account/delete/request"
	ConfirmDeleteAccount = "POST /auth/account/delete/confirm"

	InviteInfo     = "GET /auth/invite/info"
	InviteRegister = "POST /auth/invite/register"

	TwoFactorVerify  = "POST /auth/2fa/verify"
	TwoFactorResend  = "POST /auth/2fa/resend"
	TwoFactorEnable  = "POST /auth/2fa/enable"
	TwoFactorDisable = "POST /auth/2fa/disable"

	// Admin — users
	ListUsers              = "GET /admin/users"
	GetUserDetail          = "GET /admin/users/{id}"
	AdminCreateUser        = "POST /admin/users"
	UpdateUserRole         = "PATCH /admin/users/{id}/role"
	BanUser                = "PATCH /admin/users/{id}/ban"
	UnbanUser              = "PATCH /admin/users/{id}/unban"
	DeleteUser             = "DELETE /admin/users/{id}"
	AdminListUserSessions  = "GET /admin/users/{id}/sessions"
	AdminRevokeUserSession = "DELETE /admin/users/{id}/sessions/{sessionId}"
	RevokeUserSessions     = "DELETE /admin/users/{id}/sessions"

	// Admin — audit logs
	AdminListAuditLogs     = "GET /admin/audit-logs"
	AdminListUserAuditLogs = "GET /admin/users/{id}/audit-logs"

	// Admin — invites (EnableInvite)
	CreateInvite     = "POST /admin/invites"
	ListInvites      = "GET /admin/invites"
	RevokeInvite     = "DELETE /admin/invites/{id}"
	ResendInvite     = "POST /admin/invites/{id}/resend"
	HardDeleteInvite = "DELETE /admin/invites/{id}/hard"

	// OAuth (EnableOAuth)
	OAuthInitiate     = "GET /auth/oauth/{provider}"
	OAuthCallbackGet  = "GET /auth/oauth/{provider}/callback"
	OAuthCallbackPost = "POST /auth/oauth/{provider}/callback"
	OAuthLink         = "POST /auth/oauth/{provider}/link"
	OAuthUnlink       = "POST /auth/oauth/{provider}/unlink"
	OAuthProviders    = "GET /auth/oauth/providers"

	// Organizations
	CreateOrg           = "POST /auth/orgs"
	ListUserOrgs        = "GET /auth/orgs"
	GetOrg              = "GET /auth/orgs/{orgID}"
	UpdateOrg           = "PUT /auth/orgs/{orgID}"
	DeleteOrg           = "DELETE /auth/orgs/{orgID}"
	ListOrgMembers      = "GET /auth/orgs/{orgID}/members"
	RemoveOrgMember     = "DELETE /auth/orgs/{orgID}/members/{userID}"
	UpdateOrgMemberRole = "PATCH /auth/orgs/{orgID}/members/{userID}/role"
	LeaveOrg            = "POST /auth/orgs/{orgID}/leave"
	SetActiveOrg        = "PUT /auth/orgs/active"
	ClearActiveOrg      = "DELETE /auth/orgs/active"
	CreateOrgInvite     = "POST /auth/orgs/{orgID}/invites"
	AcceptOrgInvite     = "POST /auth/orgs/invites/accept"
	ListOrgInvites      = "GET /auth/orgs/{orgID}/invites"
	ResendOrgInvite     = "POST /auth/orgs/{orgID}/invites/{inviteID}/resend"
	DeleteOrgInvite     = "DELETE /auth/orgs/{orgID}/invites/{inviteID}"
)

// Glob rewrites a "METHOD /path/{param}" route into "METHOD /path/*", the
// form the rate-limit table matches against — one wildcard segment per
// ServeMux path parameter, regardless of the parameter's name.
func Glob(pattern string) string {
	segments := strings.Split(pattern, "/")
	for i, seg := range segments {
		if strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}") {
			segments[i] = "*"
		}
	}
	return strings.Join(segments, "/")
}
