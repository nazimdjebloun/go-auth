// Package routes is the single source of truth for every HTTP route
// go-auth mounts: the canonical "METHOD /path" string used to register it
// on a ServeMux, and everything derived from that path (the rate-limit
// table's glob form). It imports nothing else in this module, so anything
// is free to depend on it without risking an import cycle.
package routes

import "strings"

// Register and the following constants define the routes mounted by go-auth.
const (
	Register       = "POST /auth/register"
	Login          = "POST /auth/login"
	AdminLogin     = "POST /auth/admin/login"
	Logout         = "POST /auth/logout"
	ForgotPassword = "POST /auth/forgot-pass" + "word"
	ResetPassword  = "POST /auth/reset-pass" + "word"
	ChangePassword = "POST /auth/change-pass" + "word"

	SetPasswordRequest = "POST /auth/set-pass" + "word/request"
	SetPasswordConfirm = "POST /auth/set-pass" + "word/confirm"

	VerifyEmail              = "POST /auth/verify-email"
	ResendVerification       = "POST /auth/resend-verification"
	ResendVerificationPublic = "POST /auth/verify-email/resend"

	Me         = "GET /auth/me"
	CSRFToken  = "GET /auth/csrf-" + "token"
	ChangeName = "PUT /auth/name"

	ListSessions       = "GET /auth/sessions"
	AllSessions        = "GET /auth/sessions/all"
	RevokeSession      = "DELETE /auth/sessions/{id}"
	RevokeManySessions = "POST /auth/sessions/revoke"
	RevokeAllSessions  = "DELETE /auth/sessions"
	RefreshToken       = "POST /auth/" + "refresh"

	DeleteAccount        = "DELETE /auth/account"
	RequestDeleteAccount = "POST /auth/account/delete/request"
	ConfirmDeleteAccount = "POST /auth/account/delete/confirm"

	InviteInfo     = "GET /auth/invite/info"
	InviteRegister = "POST /auth/invite/register"

	TwoFactorVerify  = "POST /auth/2fa/verify"
	TwoFactorResend  = "POST /auth/2fa/resend"
	TwoFactorEnable  = "POST /auth/2fa/enable"
	TwoFactorDisable = "POST /auth/2fa/disable"

	// ListUsers and the following constants define administrator user routes.
	ListUsers              = "GET /admin/users"
	AdminCountUsers        = "GET /admin/users/count"
	GetUserDetail          = "GET /admin/users/{id}"
	AdminCreateUser        = "POST /admin/users"
	UpdateUserRole         = "PATCH /admin/users/{id}/role"
	BanUser                = "PATCH /admin/users/{id}/ban"
	UnbanUser              = "PATCH /admin/users/{id}/unban"
	DeleteUser             = "DELETE /admin/users/{id}"
	AdminListUserSessions  = "GET /admin/users/{id}/sessions"
	AdminRevokeUserSession = "DELETE /admin/users/{id}/sessions/{sessionId}"
	RevokeUserSessions     = "DELETE /admin/users/{id}/sessions"

	// AdminListSessions and the following constants define administrator session and bulk-user routes.
	AdminListSessions      = "GET /admin/sessions"
	AdminCountSessions     = "GET /admin/sessions/count"
	BulkBanUsers           = "POST /admin/users/bulk/ban"
	BulkUnbanUsers         = "POST /admin/users/bulk/unban"
	BulkDeleteUsers        = "POST /admin/users/bulk/delete"
	BulkRevokeUserSessions = "POST /admin/users/bulk/revoke-sessions"

	// AdminListAuditLogs and the following constants define administrator audit-log routes.
	AdminListAuditLogs      = "GET /admin/audit-logs"
	AdminCountAuditLogs     = "GET /admin/audit-logs/count"
	AdminListUserAuditLogs  = "GET /admin/users/{id}/audit-logs"
	AdminCountUserAuditLogs = "GET /admin/users/{id}/audit-logs/count"

	// AdminStats and the following constants define administrator statistics routes.
	AdminStats             = "GET /admin/stats"
	AdminRegistrationTrend = "GET /admin/stats/registrations"
	AdminLoginActivity     = "GET /admin/stats/logins"

	// AdminListOrgs and the following constants define administrator organization routes.
	AdminListOrgs            = "GET /admin/orgs"
	AdminCountOrgs           = "GET /admin/orgs/count"
	AdminGetOrg              = "GET /admin/orgs/{orgID}"
	AdminListOrgMembers      = "GET /admin/orgs/{orgID}/members"
	AdminCountOrgMembers     = "GET /admin/orgs/{orgID}/members/count"
	AdminAddOrgMember        = "POST /admin/orgs/{orgID}/members"
	AdminDeleteOrg           = "DELETE /admin/orgs/{orgID}"
	AdminRemoveOrgMember     = "DELETE /admin/orgs/{orgID}/members/{userID}"
	AdminUpdateOrgMemberRole = "PATCH /admin/orgs/{orgID}/members/{userID}/role"
	AdminListUserOrgs        = "GET /admin/users/{id}/orgs"
	AdminCountUserOrgs       = "GET /admin/users/{id}/orgs/count"

	// CreateInvite and the following constants define administrator invite routes.
	CreateInvite      = "POST /admin/invites"
	ListInvites       = "GET /admin/invites"
	AdminCountInvites = "GET /admin/invites/count"
	RevokeInvite      = "DELETE /admin/invites/{id}"
	ResendInvite      = "POST /admin/invites/{id}/resend"
	HardDeleteInvite  = "DELETE /admin/invites/{id}/hard"

	// BulkSendInvites and the following constants define bulk invite routes.
	BulkSendInvites   = "POST /admin/invites/bulk/send"
	BulkResendInvites = "POST /admin/invites/bulk/resend"
	BulkRevokeInvites = "POST /admin/invites/bulk/revoke"
	BulkDeleteInvites = "POST /admin/invites/bulk/delete"

	// OAuthInitiate and the following constants define OAuth routes.
	OAuthInitiate     = "GET /auth/oauth/{provider}"
	OAuthCallbackGet  = "GET /auth/oauth/{provider}/callback"
	OAuthCallbackPost = "POST /auth/oauth/{provider}/callback"
	OAuthLink         = "POST /auth/oauth/{provider}/link"
	OAuthUnlink       = "POST /auth/oauth/{provider}/unlink"
	OAuthProviders    = "GET /auth/oauth/providers"

	// CreateOrg and the following constants define organization routes.
	CreateOrg           = "POST /auth/orgs"
	ListUserOrgs        = "GET /auth/orgs"
	CountUserOrgs       = "GET /auth/orgs/count"
	GetOrg              = "GET /auth/orgs/{orgID}"
	UpdateOrg           = "PUT /auth/orgs/{orgID}"
	DeleteOrg           = "DELETE /auth/orgs/{orgID}"
	ListOrgMembers      = "GET /auth/orgs/{orgID}/members"
	CountOrgMembers     = "GET /auth/orgs/{orgID}/members/count"
	RemoveOrgMember     = "DELETE /auth/orgs/{orgID}/members/{userID}"
	UpdateOrgMemberRole = "PATCH /auth/orgs/{orgID}/members/{userID}/role"
	LeaveOrg            = "POST /auth/orgs/{orgID}/leave"
	SetActiveOrg        = "PUT /auth/orgs/active"
	ClearActiveOrg      = "DELETE /auth/orgs/active"
	CreateOrgInvite     = "POST /auth/orgs/{orgID}/invites"
	AcceptOrgInvite     = "POST /auth/orgs/invites/accept"
	ListOrgInvites      = "GET /auth/orgs/{orgID}/invites"
	CountOrgInvites     = "GET /auth/orgs/{orgID}/invites/count"
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
