package goauth

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
)

// Services exposes authentication flows and actor-attributed management.
// Account binds self-service to an authenticated actor; Trusted exposes primitives.
type Services struct {
	Email          EmailOperations
	Auth           AuthOperations
	Password       PasswordOperations
	Session        SessionOperations
	Verify         VerifyOperations
	Invite         InviteOperations
	AdminInvite    AdminInviteOperations
	AdminOrg       AdminOrgOperations
	Admin          AdminOperations
	OAuth          OAuthOperations
	Org            OrgOperations
	OrgInvite      OrgInviteOperations
	TwoFactor      TwoFactorOperations
	AppPermissions AppPermissionsOperations
	OrgPermissions OrgPermissionsOperations
}

// EmailOperations is available only when SecurityConfig.AllowEmailChange is enabled.
// Transports supply trusted account/session attribution in every input.
type EmailOperations interface {
	RequestEmailChange(context.Context, api.RequestEmailChangeInput) (*api.EmailChangeResult, error)
	ConfirmEmailChange(context.Context, api.ConfirmEmailChangeInput) error
	ResendEmailChange(context.Context, api.ResendEmailChangeInput) (*api.EmailChangeResult, error)
	CancelEmailChange(context.Context, api.CancelEmailChangeInput) error
}

var _ EmailOperations = (*service.EmailService)(nil)

// AppPermissionsOperations is available only with WithAppPermissions enabled.
// Actor identity must come from trusted backend authentication.
type AppPermissionsOperations interface {
	CreatePermission(context.Context, api.CreateAppPermissionInput) (*domain.AppPermission, error)
	UpdatePermission(context.Context, api.UpdateAppPermissionInput) (*domain.AppPermission, error)
	DeletePermission(context.Context, api.DeleteAppPermissionInput) error
	ListPermissions(context.Context, api.ListAppPermissionsInput) ([]domain.AppPermission, error)
	CreateRole(context.Context, api.CreateAppRoleInput) (*domain.AppRole, error)
	UpdateRole(context.Context, api.UpdateAppRoleInput) (*domain.AppRole, error)
	DeleteRole(context.Context, api.DeleteAppRoleInput) error
	ListRoles(context.Context, api.ListAppRolesInput) ([]domain.AppRole, error)
	SetRolePermissions(context.Context, api.SetAppRolePermissionsInput) (*domain.AppRole, error)
	SetUserRole(context.Context, api.SetAppUserRoleInput) (*api.AppUserRoleResult, error)
	GetUserRole(context.Context, api.GetAppUserRoleInput) (*api.AppUserRoleResult, error)
	CheckPermission(context.Context, api.CheckAppPermissionInput) (*api.AppPermissionDecision, error)
	RequirePermission(context.Context, api.CheckAppPermissionInput) error
	ListEffectivePermissions(context.Context, api.ListAppEffectivePermissionsInput) (*api.AppAccess, error)
	LibraryPermissionCatalog() []domain.AppLibraryPermissionDefinition
	UpdateLibraryPermissions(context.Context, api.UpdateAppLibraryPermissionsInput) (*api.UpdateAppLibraryPermissionsResult, error)
}

var _ AppPermissionsOperations = (*service.AppPermissionsService)(nil)

// OrgPermissionsOperations is available only with WithOrgPermissions enabled.
// Actor identity must come from trusted backend authentication.
type OrgPermissionsOperations interface {
	Initialize(context.Context, api.InitializeOrgPermissionsInput) error
	CreatePermission(context.Context, api.CreateOrgPermissionInput) (*domain.OrgPermission, error)
	UpdatePermission(context.Context, api.UpdateOrgPermissionInput) (*domain.OrgPermission, error)
	DeletePermission(context.Context, api.DeleteOrgPermissionInput) error
	ListPermissions(context.Context, api.ListOrgPermissionsInput) ([]domain.OrgPermission, error)
	CreateRole(context.Context, api.CreateOrgRoleInput) (*domain.OrgPermissionRole, error)
	UpdateRole(context.Context, api.UpdateOrgRoleInput) (*domain.OrgPermissionRole, error)
	DeleteRole(context.Context, api.DeleteOrgRoleInput) error
	ListRoles(context.Context, api.ListOrgRolesInput) ([]domain.OrgPermissionRole, error)
	SetRolePermissions(context.Context, api.SetOrgRolePermissionsInput) (*domain.OrgPermissionRole, error)
	SetMemberRole(context.Context, api.SetOrgMemberRoleInput) (*api.OrgMemberRoleResult, error)
	GetMemberRole(context.Context, api.GetOrgMemberRoleInput) (*api.OrgMemberRoleResult, error)
	CheckPermission(context.Context, api.CheckOrgPermissionInput) (*api.OrgPermissionDecision, error)
	RequirePermission(context.Context, api.CheckOrgPermissionInput) error
	ListEffectivePermissions(context.Context, api.ListOrgEffectivePermissionsInput) (*api.OrgAccess, error)
	LibraryPermissionCatalog() []domain.OrgLibraryPermissionDefinition
	UpdateLibraryPermissions(context.Context, api.UpdateOrgLibraryPermissionsInput) (*api.UpdateOrgLibraryPermissionsResult, error)
}

var _ OrgPermissionsOperations = (*service.OrgPermissionsService)(nil)

// AuthOperations authenticates credentials or consumes an account-deletion proof.
type AuthOperations interface {
	Register(ctx context.Context, input api.RegisterInput) (*api.RegisterResult, error)
	Login(ctx context.Context, input api.LoginInput) (*api.LoginResult, error)
	AdminLogin(ctx context.Context, input api.LoginInput) (*api.LoginResult, error)
	ConfirmDeleteAccount(ctx context.Context, input api.ConfirmDeleteAccountInput) error
}

// PasswordOperations requests recovery or consumes password-reset/setup proofs.
type PasswordOperations interface {
	// ForgotPassword acknowledges durable queue acceptance, not account existence or delivery.
	ForgotPassword(ctx context.Context, input api.ForgotPasswordInput) error
	ResetPassword(ctx context.Context, input api.ResetPasswordInput) error
	ConfirmSetPassword(ctx context.Context, input api.ConfirmSetPasswordInput) error
}

// SessionOperations rotates credentials using possession of a raw refresh token.
// It cannot issue a session from a user ID; that primitive belongs to Trusted.
type SessionOperations interface {
	RefreshSession(ctx context.Context, rawRefreshToken string) (*api.SessionResult, error)
}

// VerifyOperations consumes verification codes or queues account-independent recovery.
type VerifyOperations interface {
	VerifyEmail(ctx context.Context, code string) (*domain.User, error)
	// SendVerificationByEmail returns the generic acknowledgement sentinel after enqueueing.
	SendVerificationByEmail(ctx context.Context, email string) (*api.VerificationResult, error)
}

// InviteOperations inspects or consumes signup invitation credentials.
type InviteOperations interface {
	GetInviteByToken(ctx context.Context, rawToken string) (*domain.Invite, error)
	CompleteInviteRegistration(ctx context.Context, input api.CompleteInviteInput) (*api.CompleteInviteResult, error)
}

// AdminOperations exposes the admin service methods available to callers.
type AdminOperations interface {
	GetStats(ctx context.Context, input api.GetAdminStatsInput) (*api.AdminStats, error)
	GetRegistrationTrend(ctx context.Context, input api.StatsRangeInput) ([]api.DailyCount, error)
	GetLoginActivity(ctx context.Context, input api.LoginActivityInput) ([]api.DailyCount, error)
	RevokeUserSessions(ctx context.Context, input api.RevokeUserSessionsInput) error
	ListSessions(ctx context.Context, input api.AdminListSessionsInput) (*api.AdminListSessionsResult, error)
	CountSessions(ctx context.Context, input api.AdminListSessionsInput) (int, error)
	ListUserSessions(ctx context.Context, input api.AdminListUserSessionsInput) ([]domain.Session, int, error)
	RevokeUserSession(ctx context.Context, input api.RevokeUserSessionInput) error
	BulkBanUsers(ctx context.Context, input api.BulkUserActionInput) (*api.BulkUserActionResult, error)
	BulkUnbanUsers(ctx context.Context, input api.BulkUserActionInput) (*api.BulkUserActionResult, error)
	BulkDeleteUsers(ctx context.Context, input api.BulkUserActionInput) (*api.BulkUserActionResult, error)
	BulkRevokeUserSessions(ctx context.Context, input api.BulkUserActionInput) (*api.BulkUserActionResult, error)
	ListAuditLogs(ctx context.Context, input api.AdminListAuditLogsInput) (*api.AdminListAuditLogsResult, error)
	CountAuditLogs(ctx context.Context, input api.AdminListAuditLogsInput) (int, error)
	ListUsers(ctx context.Context, input api.AdminListUsersInput) (*api.AdminListUsersResult, error)
	CountUsers(ctx context.Context, input api.AdminListUsersInput) (int, error)
	BanUser(ctx context.Context, input api.BanUserInput) error
	UnbanUser(ctx context.Context, input api.UnbanUserInput) error
	UpdateUserRole(ctx context.Context, input api.UpdateUserRoleInput) error
	DeleteUser(ctx context.Context, input api.DeleteUserInput) error
	CreateUser(ctx context.Context, input api.CreateUserInput) (*domain.User, error)
	GetUserDetail(ctx context.Context, input api.GetUserDetailInput) (*api.AdminUserDetail, error)
}

// OAuthOperations performs provider authentication and invitation signup flows.
// Account(actor).OAuth supplies actor-bound provider linking and removal.
type OAuthOperations interface {
	InitiateInvite(ctx context.Context, input api.OAuthInviteInput) (*api.OAuthInitiation, error)
	VerifyInviteEmail(ctx context.Context, input api.OAuthInviteVerifyInput) (*api.OAuthCallbackResult, error)
	Initiate(ctx context.Context, providerName string) (*api.OAuthInitiation, error)
	Callback(ctx context.Context, input api.OAuthCallbackInput) (*api.OAuthCallbackResult, error)
}

// OrgOperations manages tenant resources using trusted actor attribution and
// the existing current membership/permission checks. Use Account(actor).Org for
// self creation, membership listings and active-organization selection.
type OrgOperations interface {
	GetByID(ctx context.Context, input api.GetOrgInput) (*domain.Organization, error)
	GetBySlug(ctx context.Context, input api.GetOrgBySlugInput) (*domain.Organization, error)
	UpdateOrg(ctx context.Context, input api.UpdateOrgInput) (*domain.Organization, error)
	DeleteOrg(ctx context.Context, input api.DeleteOrgInput) error
	AddMember(ctx context.Context, input api.AddMemberInput) error
	RemoveMember(ctx context.Context, input api.RemoveMemberInput) error
	UpdateMemberRole(ctx context.Context, input api.UpdateMemberRoleInput) error
	ListMembers(ctx context.Context, input api.ListMembersInput) (*api.ListMembersResult, error)
	CountMembers(ctx context.Context, input api.ListMembersInput) (int, error)
}

// OrgInviteOperations manages invitations with existing tenant authorization.
// Acceptance as the current user belongs to Account(actor).OrgInvite.
type OrgInviteOperations interface {
	CreateOrgInvite(ctx context.Context, input api.CreateOrgInviteInput) (*domain.OrgInvite, error)
	ListOrgInvites(ctx context.Context, input api.ListOrgInvitesInput) (*api.ListOrgInvitesResult, error)
	CountOrgInvites(ctx context.Context, input api.ListOrgInvitesInput) (int, error)
	DeleteOrgInvite(ctx context.Context, input api.DeleteOrgInviteInput) error
	ResendOrgInviteEmail(ctx context.Context, input api.ResendOrgInviteEmailInput) error
}

// TwoFactorOperations verifies or resends an existing browser-bound login challenge.
// Start login through Auth.Login/AdminLogin; arbitrary-ID Challenge is trusted.
type TwoFactorOperations interface {
	Verify(ctx context.Context, input api.TwoFactorVerifyInput) (*api.TwoFactorVerifyResult, error)
	Resend(ctx context.Context, input api.TwoFactorResendInput) (*api.ChallengeResult, error)
}

// IsSessionError reports whether err is a session lookup failure.
func IsSessionError(err error) bool { return service.IsSessionError(err) }

var (
	_ AuthOperations      = (*service.AuthService)(nil)
	_ PasswordOperations  = (*service.PasswordService)(nil)
	_ SessionOperations   = (*service.SessionService)(nil)
	_ VerifyOperations    = (*service.VerificationService)(nil)
	_ InviteOperations    = (*service.InviteService)(nil)
	_ AdminOperations     = (*service.AdminService)(nil)
	_ OAuthOperations     = (*service.OAuthService)(nil)
	_ OrgOperations       = (*service.OrgService)(nil)
	_ OrgInviteOperations = (*service.OrgInviteService)(nil)
	_ TwoFactorOperations = (*service.TwoFactorService)(nil)
)

// AdminInviteOperations requires trusted administrator attribution and current authorization.
type AdminInviteOperations interface {
	CreateInvite(ctx context.Context, input api.CreateInviteInput) (*domain.Invite, error)
	ListInvites(ctx context.Context, input api.ListInvitesInput) ([]domain.Invite, error)
	CountInvites(ctx context.Context, input api.ListInvitesInput) (int, error)
	HardDeleteInvite(ctx context.Context, input api.HardDeleteInviteInput) error
	RevokeInvite(ctx context.Context, input api.RevokeInviteInput) error
	ResendInviteEmail(ctx context.Context, input api.ResendInviteEmailInput) error
	BulkRevokeInvites(ctx context.Context, input api.BulkInviteIDsInput) (*api.BulkInviteResult, error)
	BulkDeleteInvites(ctx context.Context, input api.BulkInviteIDsInput) (*api.BulkInviteResult, error)
	BulkSendInvites(ctx context.Context, input api.BulkInviteEmailsInput) (*api.BulkInviteResult, error)
	BulkResendInvites(ctx context.Context, input api.BulkInviteIDsInput) (*api.BulkInviteResult, error)
}

// AdminOrgOperations requires trusted administrator attribution and current authorization.
type AdminOrgOperations interface {
	AdminListOrgs(ctx context.Context, input api.AdminListOrgsInput) (*api.AdminListOrgsResult, error)
	CountOrgs(ctx context.Context, input api.AdminListOrgsInput) (int, error)
	AdminListUserOrgs(ctx context.Context, input api.AdminListUserOrgsInput) (*api.ListUserOrgsResult, error)
	AdminCountUserOrgs(ctx context.Context, input api.AdminListUserOrgsInput) (int, error)
	AdminGetOrg(ctx context.Context, input api.AdminGetOrgInput) (*domain.Organization, error)
	AdminListOrgMembers(ctx context.Context, input api.AdminListOrgMembersInput) (*api.ListMembersResult, error)
	AdminCountOrgMembers(ctx context.Context, input api.AdminListOrgMembersInput) (int, error)
	AdminDeleteOrg(ctx context.Context, input api.AdminOrgActionInput) error
	AdminAddMember(ctx context.Context, input api.AdminAddMemberInput) error
	AdminRemoveMember(ctx context.Context, input api.AdminRemoveMemberInput) error
	AdminUpdateMemberRole(ctx context.Context, input api.AdminUpdateMemberRoleInput) error
}
