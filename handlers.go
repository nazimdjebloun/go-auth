package goauth

import (
	"net/http"
)

// HandlerGroup is every route handler go-auth builds, each already wrapped in
// the middleware chain its route needs — CORS, rate limiting, CSRF, auth, and
// role or org checks as applicable. Mount registers them; reach for one
// directly only to attach it to your own router, and do not wrap it again.
//
// A handler for a disabled feature is nil: no invite handlers without
// EnableInvite, no OAuth handlers without a registered provider, no org
// handlers without OrganizationConfig.Enable.
type HandlerGroup struct {
	Register                 http.HandlerFunc
	Login                    http.HandlerFunc
	AdminLogin               http.HandlerFunc
	Logout                   http.HandlerFunc
	ForgotPassword           http.HandlerFunc
	ResetPassword            http.HandlerFunc
	ChangePassword           http.HandlerFunc
	SetPasswordRequest       http.HandlerFunc
	SetPasswordConfirm       http.HandlerFunc
	VerifyEmail              http.HandlerFunc
	ResendVerification       http.HandlerFunc
	ResendVerificationPublic http.HandlerFunc
	ListSessions             http.HandlerFunc
	GetAllSessions           http.HandlerFunc
	RevokeSession            http.HandlerFunc
	RevokeManySessions       http.HandlerFunc
	RevokeAllSessions        http.HandlerFunc
	InviteRegister           http.HandlerFunc
	VerifyTwoFactor          http.HandlerFunc
	ResendTwoFactor          http.HandlerFunc
	Enable2FA                http.HandlerFunc
	Disable2FA               http.HandlerFunc
	RefreshToken             http.HandlerFunc
	GetMe                    http.HandlerFunc
	ChangeName               http.HandlerFunc
	DeleteAccount            http.HandlerFunc
	RequestDeleteAccount     http.HandlerFunc
	ConfirmDeleteAccount     http.HandlerFunc
	ListUsers                http.HandlerFunc
	CountUsers               http.HandlerFunc
	UpdateUserRole           http.HandlerFunc
	BanUser                  http.HandlerFunc
	UnbanUser                http.HandlerFunc
	DeleteUser               http.HandlerFunc
	RevokeUserSessions       http.HandlerFunc
	AdminCreateUser          http.HandlerFunc
	AdminListUserSessions    http.HandlerFunc
	AdminRevokeUserSession   http.HandlerFunc
	GetUserDetail            http.HandlerFunc
	AdminListAuditLogs       http.HandlerFunc
	AdminListUserAuditLogs   http.HandlerFunc
	AdminStats               http.HandlerFunc
	AdminRegistrationTrend   http.HandlerFunc
	AdminLoginActivity       http.HandlerFunc
	AdminListSessions        http.HandlerFunc
	BulkBanUsers             http.HandlerFunc
	BulkUnbanUsers           http.HandlerFunc
	BulkDeleteUsers          http.HandlerFunc
	BulkRevokeUserSessions   http.HandlerFunc
	GetInviteInfo            http.HandlerFunc
	CreateInvite             http.HandlerFunc
	ListInvites              http.HandlerFunc
	RevokeInvite             http.HandlerFunc
	CountInvites             http.HandlerFunc
	ResendInvite             http.HandlerFunc
	HardDeleteInvite         http.HandlerFunc
	BulkSendInvites          http.HandlerFunc
	BulkResendInvites        http.HandlerFunc
	BulkRevokeInvites        http.HandlerFunc
	BulkDeleteInvites        http.HandlerFunc
	OAuthInitiate            http.HandlerFunc
	OAuthCallback            http.HandlerFunc
	OAuthLink                http.HandlerFunc
	OAuthUnlink              http.HandlerFunc
	OAuthProviders           http.HandlerFunc
	CSRFToken                http.HandlerFunc
	CreateOrg                http.HandlerFunc
	GetOrg                   http.HandlerFunc
	UpdateOrg                http.HandlerFunc
	DeleteOrg                http.HandlerFunc
	ListUserOrgs             http.HandlerFunc
	CountUserOrgs            http.HandlerFunc
	ListOrgMembers           http.HandlerFunc
	CountOrgMembers          http.HandlerFunc
	RemoveOrgMember          http.HandlerFunc
	UpdateOrgMemberRole      http.HandlerFunc
	AdminListOrgs            http.HandlerFunc
	AdminGetOrg              http.HandlerFunc
	AdminListOrgMembers      http.HandlerFunc
	AdminAddOrgMember        http.HandlerFunc
	AdminDeleteOrg           http.HandlerFunc
	AdminRemoveOrgMember     http.HandlerFunc
	AdminUpdateOrgMemberRole http.HandlerFunc
	AdminListUserOrgs        http.HandlerFunc
	LeaveOrg                 http.HandlerFunc
	SetActiveOrg             http.HandlerFunc
	ClearActiveOrg           http.HandlerFunc
	CreateOrgInvite          http.HandlerFunc
	AcceptOrgInvite          http.HandlerFunc
	ListOrgInvites           http.HandlerFunc
	CountOrgInvites          http.HandlerFunc
	ResendOrgInvite          http.HandlerFunc
	DeleteOrgInvite          http.HandlerFunc
}
