package goauth

import (
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/port"
)

// The service layer lives under internal/, so NewConfig(With...) is the only
// way to build a go-auth instance — the ten New*Service constructors and the
// configs they take are no longer reachable from outside this module.
//
// Its types still appear wherever a consumer actually works: the inputs and
// results of Auth.Register, Auth.Login, and every method on Auth.Services.
// These aliases keep all of that nameable, so a consumer can declare a
// variable, a struct field, or a function signature for any of it. They are
// aliases, not wrappers — goauth.RegisterInput and the service's own type are
// the same type, so there is no conversion and nothing to drift.

// AdminService is an alias for service.AdminService.
type AdminService = service.AdminService

// AuthService is an alias for service.AuthService.
type AuthService = service.AuthService

// InviteService is an alias for service.InviteService.
type InviteService = service.InviteService

// OAuthService is an alias for service.OAuthService.
type OAuthService = service.OAuthService

// OrgInviteService is an alias for service.OrgInviteService.
type OrgInviteService = service.OrgInviteService

// OrgService is an alias for service.OrgService.
type OrgService = service.OrgService

// PasswordService is an alias for service.PasswordService.
type PasswordService = service.PasswordService

// SessionService is an alias for service.SessionService.
type SessionService = service.SessionService

// TwoFactorService is an alias for service.TwoFactorService.
type TwoFactorService = service.TwoFactorService

// VerificationService is an alias for service.VerificationService.
type VerificationService = service.VerificationService

// AcceptInviteInput is an alias for service.AcceptInviteInput.
type AcceptInviteInput = service.AcceptInviteInput

// AddMemberInput is an alias for service.AddMemberInput.
type AddMemberInput = service.AddMemberInput

// AdminAddMemberInput is an alias for service.AdminAddMemberInput.
type AdminAddMemberInput = service.AdminAddMemberInput

// AdminAuditLogEntry is an alias for service.AdminAuditLogEntry.
type AdminAuditLogEntry = service.AdminAuditLogEntry

// AdminGetOrgInput is an alias for service.AdminGetOrgInput.
type AdminGetOrgInput = service.AdminGetOrgInput

// AdminListAuditLogsInput is an alias for service.AdminListAuditLogsInput.
type AdminListAuditLogsInput = service.AdminListAuditLogsInput

// AdminListAuditLogsResult is an alias for service.AdminListAuditLogsResult.
type AdminListAuditLogsResult = service.AdminListAuditLogsResult

// AdminListOrgMembersInput is an alias for service.AdminListOrgMembersInput.
type AdminListOrgMembersInput = service.AdminListOrgMembersInput

// AdminListOrgsInput is an alias for service.AdminListOrgsInput.
type AdminListOrgsInput = service.AdminListOrgsInput

// AdminListOrgsResult is an alias for service.AdminListOrgsResult.
type AdminListOrgsResult = service.AdminListOrgsResult

// AdminListSessionsInput is an alias for service.AdminListSessionsInput.
type AdminListSessionsInput = service.AdminListSessionsInput

// AdminListSessionsResult is an alias for service.AdminListSessionsResult.
type AdminListSessionsResult = service.AdminListSessionsResult

// AdminListUserOrgsInput is an alias for service.AdminListUserOrgsInput.
type AdminListUserOrgsInput = service.AdminListUserOrgsInput

// AdminListUserSessionsInput is an alias for service.AdminListUserSessionsInput.
type AdminListUserSessionsInput = service.AdminListUserSessionsInput

// AdminListUsersInput is an alias for service.AdminListUsersInput.
type AdminListUsersInput = service.AdminListUsersInput

// AdminListUsersResult is an alias for service.AdminListUsersResult.
type AdminListUsersResult = service.AdminListUsersResult

// AdminOrgActionInput is an alias for service.AdminOrgActionInput.
type AdminOrgActionInput = service.AdminOrgActionInput

// AdminRemoveMemberInput is an alias for service.AdminRemoveMemberInput.
type AdminRemoveMemberInput = service.AdminRemoveMemberInput

// AdminStats is an alias for service.AdminStats.
type AdminStats = service.AdminStats

// AdminUpdateMemberRoleInput is an alias for service.AdminUpdateMemberRoleInput.
type AdminUpdateMemberRoleInput = service.AdminUpdateMemberRoleInput

// AdminUserDetail is an alias for service.AdminUserDetail.
type AdminUserDetail = service.AdminUserDetail

// BanUserInput is an alias for service.BanUserInput.
type BanUserInput = service.BanUserInput

// BulkActionFailure is an alias for service.BulkActionFailure.
type BulkActionFailure = service.BulkActionFailure

// BulkInviteEmailsInput is an alias for service.BulkInviteEmailsInput.
type BulkInviteEmailsInput = service.BulkInviteEmailsInput

// BulkInviteFailure is an alias for service.BulkInviteFailure.
type BulkInviteFailure = service.BulkInviteFailure

// BulkInviteIDsInput is an alias for service.BulkInviteIDsInput.
type BulkInviteIDsInput = service.BulkInviteIDsInput

// BulkInviteResult is an alias for service.BulkInviteResult.
type BulkInviteResult = service.BulkInviteResult

// BulkUserActionInput is an alias for service.BulkUserActionInput.
type BulkUserActionInput = service.BulkUserActionInput

// BulkUserActionResult is an alias for service.BulkUserActionResult.
type BulkUserActionResult = service.BulkUserActionResult

// ChallengeResult is an alias for service.ChallengeResult.
type ChallengeResult = service.ChallengeResult

// ChangePasswordInput is an alias for service.ChangePasswordInput.
type ChangePasswordInput = service.ChangePasswordInput

// ClearActiveOrgInput is an alias for service.ClearActiveOrgInput.
type ClearActiveOrgInput = service.ClearActiveOrgInput

// CompleteInviteInput is an alias for service.CompleteInviteInput.
type CompleteInviteInput = service.CompleteInviteInput

// CompleteInviteResult is an alias for service.CompleteInviteResult.
type CompleteInviteResult = service.CompleteInviteResult

// ConfirmDeleteAccountInput is an alias for service.ConfirmDeleteAccountInput.
type ConfirmDeleteAccountInput = service.ConfirmDeleteAccountInput

// ConfirmSetPasswordInput is an alias for service.ConfirmSetPasswordInput.
type ConfirmSetPasswordInput = service.ConfirmSetPasswordInput

// CreateInviteInput is an alias for service.CreateInviteInput.
type CreateInviteInput = service.CreateInviteInput

// CreateOrgInput is an alias for service.CreateOrgInput.
type CreateOrgInput = service.CreateOrgInput

// CreateOrgInviteInput is an alias for service.CreateOrgInviteInput.
type CreateOrgInviteInput = service.CreateOrgInviteInput

// CreateUserInput is an alias for service.CreateUserInput.
type CreateUserInput = service.CreateUserInput

// DeleteOrgInput is an alias for service.DeleteOrgInput.
type DeleteOrgInput = service.DeleteOrgInput

// DeleteUserInput is an alias for service.DeleteUserInput.
type DeleteUserInput = service.DeleteUserInput

// EmailData is an alias for service.EmailData.
type EmailData = service.EmailData

// ForgotPasswordInput is an alias for service.ForgotPasswordInput.
type ForgotPasswordInput = service.ForgotPasswordInput

// GetOrgBySlugInput is an alias for service.GetOrgBySlugInput.
type GetOrgBySlugInput = service.GetOrgBySlugInput

// GetOrgInput is an alias for service.GetOrgInput.
type GetOrgInput = service.GetOrgInput

// GetOrgMembershipInput is an alias for service.GetOrgMembershipInput.
type GetOrgMembershipInput = service.GetOrgMembershipInput

// GetUserDetailInput is an alias for service.GetUserDetailInput.
type GetUserDetailInput = service.GetUserDetailInput

// LeaveOrgInput is an alias for service.LeaveOrgInput.
type LeaveOrgInput = service.LeaveOrgInput

// ListInvitesInput is an alias for service.ListInvitesInput.
type ListInvitesInput = service.ListInvitesInput

// ListMembersInput is an alias for service.ListMembersInput.
type ListMembersInput = service.ListMembersInput

// ListMembersResult is an alias for service.ListMembersResult.
type ListMembersResult = service.ListMembersResult

// ListOrgInvitesInput is an alias for service.ListOrgInvitesInput.
type ListOrgInvitesInput = service.ListOrgInvitesInput

// ListOrgInvitesResult is an alias for service.ListOrgInvitesResult.
type ListOrgInvitesResult = service.ListOrgInvitesResult

// ListSessionsResult is an alias for service.ListSessionsResult.
type ListSessionsResult = service.ListSessionsResult

// ListUserOrgsInput is an alias for service.ListUserOrgsInput.
type ListUserOrgsInput = service.ListUserOrgsInput

// ListUserOrgsResult is an alias for service.ListUserOrgsResult.
type ListUserOrgsResult = service.ListUserOrgsResult

// LoginActivityInput is an alias for service.LoginActivityInput.
type LoginActivityInput = service.LoginActivityInput

// LoginInput is an alias for service.LoginInput.
type LoginInput = service.LoginInput

// LoginResult is an alias for service.LoginResult.
type LoginResult = service.LoginResult

// OAuthCallbackResult is an alias for service.OAuthCallbackResult.
type OAuthCallbackResult = service.OAuthCallbackResult

// OAuthInitiation is an alias for service.OAuthInitiation.
type OAuthInitiation = service.OAuthInitiation

// RegisterInput is an alias for service.RegisterInput.
type RegisterInput = service.RegisterInput

// RegisterResult is an alias for service.RegisterResult.
type RegisterResult = service.RegisterResult

// RemoveMemberInput is an alias for service.RemoveMemberInput.
type RemoveMemberInput = service.RemoveMemberInput

// ResetPasswordInput is an alias for service.ResetPasswordInput.
type ResetPasswordInput = service.ResetPasswordInput

// RevokeUserSessionInput is an alias for service.RevokeUserSessionInput.
type RevokeUserSessionInput = service.RevokeUserSessionInput

// RevokeUserSessionsInput is an alias for service.RevokeUserSessionsInput.
type RevokeUserSessionsInput = service.RevokeUserSessionsInput

// SessionResult is an alias for domain.SessionResult.
type SessionResult = domain.SessionResult

// SetActiveOrgInput is an alias for service.SetActiveOrgInput.
type SetActiveOrgInput = service.SetActiveOrgInput

// StatsRangeInput is an alias for service.StatsRangeInput.
type StatsRangeInput = service.StatsRangeInput

// TwoFactorVerifyResult is an alias for service.TwoFactorVerifyResult.
type TwoFactorVerifyResult = service.TwoFactorVerifyResult

// UnbanUserInput is an alias for service.UnbanUserInput.
type UnbanUserInput = service.UnbanUserInput

// UpdateMemberRoleInput is an alias for service.UpdateMemberRoleInput.
type UpdateMemberRoleInput = service.UpdateMemberRoleInput

// UpdateOrgInput is an alias for service.UpdateOrgInput.
type UpdateOrgInput = service.UpdateOrgInput

// UpdateUserRoleInput is an alias for service.UpdateUserRoleInput.
type UpdateUserRoleInput = service.UpdateUserRoleInput

// VerificationResult is an alias for service.VerificationResult.
type VerificationResult = service.VerificationResult

// SortDirection controls whether a list is ordered from low to high or high
// to low. Use SortAscending or SortDescending.
type SortDirection = port.SortDirection

// SortAscending and SortDescending define sort direction values.
const (
	SortAscending  = port.SortAscending
	SortDescending = port.SortDescending
)

// UserSortField identifies a supported user-list ordering.
type UserSortField = port.UserSortField

// UserSortCreatedAt and UserSortUpdatedAt define user sort fields.
const (
	UserSortCreatedAt = port.UserSortCreatedAt
	UserSortUpdatedAt = port.UserSortUpdatedAt
)

// SessionSortField identifies a supported session-list ordering.
type SessionSortField = port.SessionSortField

// SessionSortCreatedAt and the following values define session sort fields.
const (
	SessionSortCreatedAt    = port.SessionSortCreatedAt
	SessionSortExpiresAt    = port.SessionSortExpiresAt
	SessionSortLastActiveAt = port.SessionSortLastActiveAt
)

// InviteSortField identifies a supported platform-invite-list ordering.
type InviteSortField = port.InviteSortField

// InviteSortCreatedAt and the following values define invite sort fields.
const (
	InviteSortCreatedAt = port.InviteSortCreatedAt
	InviteSortExpiresAt = port.InviteSortExpiresAt
	InviteSortEmail     = port.InviteSortEmail
	InviteSortStatus    = port.InviteSortStatus
)

// OrgMemberSortField identifies a supported organization-member-list ordering.
type OrgMemberSortField = port.OrgMemberSortField

// OrgMemberSortJoinedAt and the following values define member sort fields.
const (
	OrgMemberSortJoinedAt = port.OrgMemberSortJoinedAt
	OrgMemberSortRole     = port.OrgMemberSortRole
	OrgMemberSortName     = port.OrgMemberSortName
	OrgMemberSortEmail    = port.OrgMemberSortEmail
)

// UserOrgSortField identifies a supported user's organization-list ordering.
type UserOrgSortField = port.UserOrgSortField

// UserOrgSortName and the following values define user organization sort fields.
const (
	UserOrgSortName        = port.UserOrgSortName
	UserOrgSortCreatedAt   = port.UserOrgSortCreatedAt
	UserOrgSortMemberCount = port.UserOrgSortMemberCount
)

// OrgSortField identifies a supported platform organization-list ordering.
type OrgSortField = port.OrgSortField

// OrgSortName and the following values define organization sort fields.
const (
	OrgSortName        = port.OrgSortName
	OrgSortCreatedAt   = port.OrgSortCreatedAt
	OrgSortMemberCount = port.OrgSortMemberCount
)

// OrgInviteSortField identifies a supported organization-invite-list ordering.
type OrgInviteSortField = port.OrgInviteSortField

// OrgInviteSortCreatedAt and the following values define organization invite sort fields.
const (
	OrgInviteSortCreatedAt = port.OrgInviteSortCreatedAt
	OrgInviteSortExpiresAt = port.OrgInviteSortExpiresAt
	OrgInviteSortEmail     = port.OrgInviteSortEmail
	OrgInviteSortRole      = port.OrgInviteSortRole
)

// IsSessionError reports whether err is a session lookup failure
// (not found or expired), including wrapped values. Alias for the service
// implementation — the service package is internal and cannot be imported
// from another module, so this is the name external callers use.
var IsSessionError = service.IsSessionError
