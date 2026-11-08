package goauth

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/port"
)

// TrustedServices exposes backend primitives, including unchecked session
// issuance and identity-attributed operations. Possession of these capabilities
// requires trusted application wiring. They are not client-facing auth flows.
// Prefer Services, Account and narrow consumer interfaces for ordinary code.
type TrustedServices struct {
	Email          EmailOperations
	Auth           TrustedAuthOperations
	Password       TrustedPasswordOperations
	Session        TrustedSessionOperations
	Verify         TrustedVerifyOperations
	Invite         TrustedInviteOperations
	Admin          AdminOperations
	OAuth          TrustedOAuthOperations
	Org            TrustedOrgOperations
	OrgInvite      TrustedOrgInviteOperations
	TwoFactor      TrustedTwoFactorOperations
	AuditLog       port.AuditLogRepository
	AppPermissions AppPermissionsOperations
	OrgPermissions OrgPermissionsOperations
}

// TrustedAuthOperations exposes backend integration primitives.
// Inputs attributed only by IDs require prior authentication/authorization by the caller.
type TrustedAuthOperations interface {
	Register(ctx context.Context, input api.RegisterInput) (*api.RegisterResult, error)
	Login(ctx context.Context, input api.LoginInput) (*api.LoginResult, error)
	AdminLogin(ctx context.Context, input api.LoginInput) (*api.LoginResult, error)
	ValidateSession(ctx context.Context, tokenRaw string) (*domain.User, *domain.Session, error)
	Logout(ctx context.Context, sessionID string) error
	ChangeName(ctx context.Context, input api.ChangeNameInput) error
	DeleteAccount(ctx context.Context, input api.DeleteAccountInput) error
	RequestDeleteAccount(ctx context.Context, userID string) error
	ConfirmDeleteAccount(ctx context.Context, input api.ConfirmDeleteAccountInput) error
}

var _ TrustedAuthOperations = (*service.AuthService)(nil)

// TrustedPasswordOperations exposes backend integration primitives.
// Inputs attributed only by IDs require prior authentication/authorization by the caller.
type TrustedPasswordOperations interface {
	// ForgotPassword durably queues a request. Success does not confirm account
	// existence or delivery; email is processed in the background.
	ForgotPassword(ctx context.Context, input api.ForgotPasswordInput) error
	ResetPassword(ctx context.Context, input api.ResetPasswordInput) error
	RequestSetPassword(ctx context.Context, userID string) error
	ConfirmSetPassword(ctx context.Context, input api.ConfirmSetPasswordInput) error
	ChangePassword(ctx context.Context, input api.ChangePasswordInput) error
}

var _ TrustedPasswordOperations = (*service.PasswordService)(nil)

// TrustedSessionOperations exposes backend integration primitives.
// Inputs attributed only by IDs require prior authentication/authorization by the caller.
type TrustedSessionOperations interface {
	Create(ctx context.Context, input api.CreateSessionInput) (*api.SessionResult, error)
	RefreshSession(ctx context.Context, rawRefreshToken string) (*api.SessionResult, error)
	Validate(ctx context.Context, token string) (*domain.Session, error)
	ValidateWithUser(ctx context.Context, token string) (*domain.Session, *domain.User, error)
	Touch(ctx context.Context, input api.TouchSessionInput) error
	Revoke(ctx context.Context, token string) error
	RevokeByID(ctx context.Context, id string) error
	RevokeByIDForUser(ctx context.Context, input api.RevokeSessionForUserInput) (bool, error)
	RevokeManyForUser(ctx context.Context, input api.RevokeSessionsForUserInput) (int, error)
	RevokeAll(ctx context.Context, userID string) error
	RevokeAllExcept(ctx context.Context, input api.RevokeAllSessionsExceptInput) error
	List(ctx context.Context, input api.ListSessionsInput) ([]domain.Session, int, error)
	ListAll(ctx context.Context, userID string) ([]domain.Session, error)
}

var _ TrustedSessionOperations = (*service.SessionService)(nil)

// TrustedVerifyOperations exposes backend integration primitives.
// Inputs attributed only by IDs require prior authentication/authorization by the caller.
type TrustedVerifyOperations interface {
	VerifyEmail(ctx context.Context, code string) (*domain.User, error)
	SendVerification(ctx context.Context, user *domain.User) (*api.VerificationResult, error)
	ResendVerification(ctx context.Context, userID string) (*api.VerificationResult, error)
	// SendVerificationByEmail durably queues a public request and returns the
	// generic email_not_found sentinel; its result never reports actual delivery.
	SendVerificationByEmail(ctx context.Context, email string) (*api.VerificationResult, error)
}

var _ TrustedVerifyOperations = (*service.VerificationService)(nil)

// TrustedInviteOperations exposes backend integration primitives.
// Inputs attributed only by IDs require prior authentication/authorization by the caller.
type TrustedInviteOperations interface {
	GetInviteByToken(ctx context.Context, rawToken string) (*domain.Invite, error)
	CreateInvite(ctx context.Context, input api.CreateInviteInput) (*domain.Invite, error)
	CompleteInviteRegistration(ctx context.Context, input api.CompleteInviteInput) (*api.CompleteInviteResult, error)
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

var _ TrustedInviteOperations = (*service.InviteService)(nil)

// TrustedOAuthOperations exposes backend integration primitives.
// Inputs attributed only by IDs require prior authentication/authorization by the caller.
type TrustedOAuthOperations interface {
	InitiateInvite(ctx context.Context, input api.OAuthInviteInput) (*api.OAuthInitiation, error)
	VerifyInviteEmail(ctx context.Context, input api.OAuthInviteVerifyInput) (*api.OAuthCallbackResult, error)
	Initiate(ctx context.Context, providerName string) (*api.OAuthInitiation, error)
	InitiateLink(ctx context.Context, input api.OAuthLinkInput) (*api.OAuthInitiation, error)
	Callback(ctx context.Context, input api.OAuthCallbackInput) (*api.OAuthCallbackResult, error)
	Unlink(ctx context.Context, input api.OAuthUnlinkInput) error
	ListConnected(ctx context.Context, userID string) ([]domain.ProviderAccount, error)
}

var _ TrustedOAuthOperations = (*service.OAuthService)(nil)

// TrustedOrgOperations exposes backend integration primitives.
// Inputs attributed only by IDs require prior authentication/authorization by the caller.
type TrustedOrgOperations interface {
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

var _ TrustedOrgOperations = (*service.OrgService)(nil)

// TrustedOrgInviteOperations exposes backend integration primitives.
// Inputs attributed only by IDs require prior authentication/authorization by the caller.
type TrustedOrgInviteOperations interface {
	CreateOrgInvite(ctx context.Context, input api.CreateOrgInviteInput) (*domain.OrgInvite, error)
	AcceptInvite(ctx context.Context, input api.AcceptInviteInput) error
	ListOrgInvites(ctx context.Context, input api.ListOrgInvitesInput) (*api.ListOrgInvitesResult, error)
	CountOrgInvites(ctx context.Context, input api.ListOrgInvitesInput) (int, error)
	DeleteOrgInvite(ctx context.Context, input api.DeleteOrgInviteInput) error
	ResendOrgInviteEmail(ctx context.Context, input api.ResendOrgInviteEmailInput) error
}

var _ TrustedOrgInviteOperations = (*service.OrgInviteService)(nil)

// TrustedTwoFactorOperations exposes backend integration primitives.
// Inputs attributed only by IDs require prior authentication/authorization by the caller.
type TrustedTwoFactorOperations interface {
	RequestSettingsChallenge(ctx context.Context, input api.TwoFactorSettingsChallengeInput) (*api.ChallengeResult, error)
	CookieName() string
	CookieTTL() time.Duration
	BindingDisabled() bool
	Enforce(u *domain.User) bool
	Challenge(ctx context.Context, userID string) (*api.ChallengeResult, error)
	Verify(ctx context.Context, input api.TwoFactorVerifyInput) (*api.TwoFactorVerifyResult, error)
	Resend(ctx context.Context, input api.TwoFactorResendInput) (*api.ChallengeResult, error)
	Enable(ctx context.Context, input api.TwoFactorEnableInput) error
	Disable(ctx context.Context, input api.TwoFactorDisableInput) error
}

var _ TrustedTwoFactorOperations = (*service.TwoFactorService)(nil)
