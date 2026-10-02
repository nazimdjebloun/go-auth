package goauth

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/port"
)

// Services groups the configured programmatic capabilities.
type Services struct {
	Auth      AuthOperations
	Password  PasswordOperations
	Session   SessionOperations
	Verify    VerifyOperations
	Invite    InviteOperations
	Admin     AdminOperations
	OAuth     OAuthOperations
	Org       OrgOperations
	OrgInvite OrgInviteOperations
	TwoFactor TwoFactorOperations
	AuditLog  port.AuditLogRepository
}

// AuthOperations exposes the auth service methods available to callers.
type AuthOperations interface {
	Register(ctx context.Context, input api.RegisterInput) (*api.RegisterResult, error)
	Login(ctx context.Context, input api.LoginInput) (*api.LoginResult, error)
	AdminLogin(ctx context.Context, input api.LoginInput) (*api.LoginResult, error)
	ValidateSession(ctx context.Context, tokenRaw string) (*domain.User, *domain.Session, error)
	Logout(ctx context.Context, sessionID string) error
	ChangeName(ctx context.Context, userID, newName string) error
	DeleteAccount(ctx context.Context, userID string, password string) error
	RequestDeleteAccount(ctx context.Context, userID string) error
	ConfirmDeleteAccount(ctx context.Context, input api.ConfirmDeleteAccountInput) error
}

// PasswordOperations exposes the password service methods available to callers.
type PasswordOperations interface {
	// ForgotPassword durably queues a request. Success does not confirm account
	// existence or delivery; email is processed in the background.
	ForgotPassword(ctx context.Context, input api.ForgotPasswordInput) error
	ResetPassword(ctx context.Context, input api.ResetPasswordInput) error
	RequestSetPassword(ctx context.Context, userID string) error
	ConfirmSetPassword(ctx context.Context, input api.ConfirmSetPasswordInput) error
	ChangePassword(ctx context.Context, input api.ChangePasswordInput) error
}

// SessionOperations exposes the session service methods available to callers.
type SessionOperations interface {
	Create(ctx context.Context, userID, ip, userAgent string) (*api.SessionResult, error)
	RefreshSession(ctx context.Context, rawRefreshToken string) (*api.SessionResult, error)
	Validate(ctx context.Context, token string) (*domain.Session, error)
	ValidateWithUser(ctx context.Context, token string) (*domain.Session, *domain.User, error)
	Touch(ctx context.Context, token string, lastActiveAt time.Time) error
	Revoke(ctx context.Context, token string) error
	RevokeByID(ctx context.Context, id string) error
	RevokeByIDForUser(ctx context.Context, id, userID string) (bool, error)
	RevokeManyForUser(ctx context.Context, ids []string, userID string) (int, error)
	RevokeAll(ctx context.Context, userID string) error
	RevokeAllExcept(ctx context.Context, userID string, exceptSessionID string) error
	List(ctx context.Context, userID string, offset, limit int) ([]domain.Session, int, error)
	ListAll(ctx context.Context, userID string) ([]domain.Session, error)
}

// VerifyOperations exposes the verify service methods available to callers.
type VerifyOperations interface {
	VerifyEmail(ctx context.Context, code string) (*domain.User, error)
	SendVerification(ctx context.Context, user *domain.User) (*api.VerificationResult, error)
	ResendVerification(ctx context.Context, userID string) (*api.VerificationResult, error)
	// SendVerificationByEmail durably queues a public request and returns the
	// generic email_not_found sentinel; its result never reports actual delivery.
	SendVerificationByEmail(ctx context.Context, email string) (*api.VerificationResult, error)
}

// InviteOperations exposes the invite service methods available to callers.
type InviteOperations interface {
	GetInviteByToken(ctx context.Context, rawToken string) (*domain.Invite, error)
	CreateInvite(ctx context.Context, input api.CreateInviteInput) (*domain.Invite, error)
	CompleteInviteRegistration(ctx context.Context, input api.CompleteInviteInput) (*api.CompleteInviteResult, error)
	ListInvites(ctx context.Context, input api.ListInvitesInput) ([]domain.Invite, error)
	CountInvites(ctx context.Context, input api.ListInvitesInput) (int, error)
	HardDeleteInvite(ctx context.Context, inviteID, actorID string) error
	RevokeInvite(ctx context.Context, inviteID, actorID string) error
	ResendInviteEmail(ctx context.Context, inviteID, actorID string) error
	BulkRevokeInvites(ctx context.Context, input api.BulkInviteIDsInput) (*api.BulkInviteResult, error)
	BulkDeleteInvites(ctx context.Context, input api.BulkInviteIDsInput) (*api.BulkInviteResult, error)
	BulkSendInvites(ctx context.Context, input api.BulkInviteEmailsInput) (*api.BulkInviteResult, error)
	BulkResendInvites(ctx context.Context, input api.BulkInviteIDsInput) (*api.BulkInviteResult, error)
}

// AdminOperations exposes the admin service methods available to callers.
type AdminOperations interface {
	GetStats(ctx context.Context, actorID string) (*api.AdminStats, error)
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

// OAuthOperations exposes the oauth service methods available to callers.
type OAuthOperations interface {
	Initiate(ctx context.Context, providerName string) (*api.OAuthInitiation, error)
	InitiateLink(ctx context.Context, providerName, userID, sessionTokenHash string) (*api.OAuthInitiation, error)
	Callback(ctx context.Context, providerName, code, rawState, browserState, rawSessionToken, ip, userAgent string) (*api.OAuthCallbackResult, error)
	Unlink(ctx context.Context, userID, providerName string) error
	ListConnected(ctx context.Context, userID string) ([]domain.ProviderAccount, error)
}

// OrgOperations exposes the org service methods available to callers.
type OrgOperations interface {
	CreateOrg(ctx context.Context, input api.CreateOrgInput) (*domain.Organization, error)
	GetByID(ctx context.Context, input api.GetOrgInput) (*domain.Organization, error)
	GetBySlug(ctx context.Context, input api.GetOrgBySlugInput) (*domain.Organization, error)
	UpdateOrg(ctx context.Context, input api.UpdateOrgInput) (*domain.Organization, error)
	DeleteOrg(ctx context.Context, input api.DeleteOrgInput) error
	ListUserOrgs(ctx context.Context, input api.ListUserOrgsInput) (*api.ListUserOrgsResult, error)
	GetMembership(ctx context.Context, input api.GetOrgMembershipInput) (*domain.OrgMember, error)
	AddMember(ctx context.Context, input api.AddMemberInput) error
	RemoveMember(ctx context.Context, input api.RemoveMemberInput) error
	UpdateMemberRole(ctx context.Context, input api.UpdateMemberRoleInput) error
	LeaveOrg(ctx context.Context, input api.LeaveOrgInput) error
	ListMembers(ctx context.Context, input api.ListMembersInput) (*api.ListMembersResult, error)
	SetActiveOrg(ctx context.Context, input api.SetActiveOrgInput) error
	ClearActiveOrg(ctx context.Context, input api.ClearActiveOrgInput) error
	AdminListOrgs(ctx context.Context, input api.AdminListOrgsInput) (*api.AdminListOrgsResult, error)
	CountOrgs(ctx context.Context, input api.AdminListOrgsInput) (int, error)
	CountMembers(ctx context.Context, input api.ListMembersInput) (int, error)
	CountUserOrgs(ctx context.Context, input api.ListUserOrgsInput) (int, error)
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

// OrgInviteOperations exposes the orginvite service methods available to callers.
type OrgInviteOperations interface {
	CreateOrgInvite(ctx context.Context, input api.CreateOrgInviteInput) (*domain.OrgInvite, error)
	AcceptInvite(ctx context.Context, input api.AcceptInviteInput) error
	ListOrgInvites(ctx context.Context, input api.ListOrgInvitesInput) (*api.ListOrgInvitesResult, error)
	CountOrgInvites(ctx context.Context, input api.ListOrgInvitesInput) (int, error)
	DeleteOrgInvite(ctx context.Context, orgID, inviteID, actorID string) error
	ResendOrgInviteEmail(ctx context.Context, orgID, inviteID, actorID string) error
}

// TwoFactorOperations exposes the twofactor service methods available to callers.
type TwoFactorOperations interface {
	CookieName() string
	CookieTTL() time.Duration
	BindingDisabled() bool
	Enforce(u *domain.User) bool
	Challenge(ctx context.Context, userID string) (*api.ChallengeResult, error)
	Verify(ctx context.Context, challengeID, bindingToken, code, ip, userAgent string) (*api.TwoFactorVerifyResult, error)
	Resend(ctx context.Context, challengeID, bindingToken string) (*api.ChallengeResult, error)
	Enable(ctx context.Context, userID, password string, keepOtherSessions bool, callerSessionID string) error
	Disable(ctx context.Context, userID, password string) error
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
