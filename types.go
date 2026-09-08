package goauth

import "github.com/nazimdjebloun/go-auth/internal/service"

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

// Services reachable through Auth.Services.
type AdminService = service.AdminService
type AuthService = service.AuthService
type InviteService = service.InviteService
type OAuthService = service.OAuthService
type OrgInviteService = service.OrgInviteService
type OrgService = service.OrgService
type PasswordService = service.PasswordService
type SessionService = service.SessionService
type TwoFactorService = service.TwoFactorService
type VerificationService = service.VerificationService

// Inputs, results, and the shapes they contain.
type AcceptInviteInput = service.AcceptInviteInput
type AddMemberInput = service.AddMemberInput
type AdminAddMemberInput = service.AdminAddMemberInput
type AdminAuditLogEntry = service.AdminAuditLogEntry
type AdminGetOrgInput = service.AdminGetOrgInput
type AdminListAuditLogsInput = service.AdminListAuditLogsInput
type AdminListAuditLogsResult = service.AdminListAuditLogsResult
type AdminListOrgMembersInput = service.AdminListOrgMembersInput
type AdminListOrgsInput = service.AdminListOrgsInput
type AdminListOrgsResult = service.AdminListOrgsResult
type AdminListSessionsInput = service.AdminListSessionsInput
type AdminListSessionsResult = service.AdminListSessionsResult
type AdminListUserOrgsInput = service.AdminListUserOrgsInput
type AdminListUserSessionsInput = service.AdminListUserSessionsInput
type AdminListUsersInput = service.AdminListUsersInput
type AdminListUsersResult = service.AdminListUsersResult
type AdminOrgActionInput = service.AdminOrgActionInput
type AdminRemoveMemberInput = service.AdminRemoveMemberInput
type AdminStats = service.AdminStats
type AdminUpdateMemberRoleInput = service.AdminUpdateMemberRoleInput
type AdminUserDetail = service.AdminUserDetail
type BanUserInput = service.BanUserInput
type BulkActionFailure = service.BulkActionFailure
type BulkInviteEmailsInput = service.BulkInviteEmailsInput
type BulkInviteFailure = service.BulkInviteFailure
type BulkInviteIDsInput = service.BulkInviteIDsInput
type BulkInviteResult = service.BulkInviteResult
type BulkUserActionInput = service.BulkUserActionInput
type BulkUserActionResult = service.BulkUserActionResult
type ChallengeResult = service.ChallengeResult
type ChangePasswordInput = service.ChangePasswordInput
type ClearActiveOrgInput = service.ClearActiveOrgInput
type CompleteInviteInput = service.CompleteInviteInput
type CompleteInviteResult = service.CompleteInviteResult
type ConfirmDeleteAccountInput = service.ConfirmDeleteAccountInput
type ConfirmSetPasswordInput = service.ConfirmSetPasswordInput
type CreateInviteInput = service.CreateInviteInput
type CreateOrgInput = service.CreateOrgInput
type CreateOrgInviteInput = service.CreateOrgInviteInput
type CreateUserInput = service.CreateUserInput
type DeleteOrgInput = service.DeleteOrgInput
type DeleteUserInput = service.DeleteUserInput
type EmailData = service.EmailData
type ForgotPasswordInput = service.ForgotPasswordInput
type GetOrgBySlugInput = service.GetOrgBySlugInput
type GetOrgInput = service.GetOrgInput
type GetOrgMembershipInput = service.GetOrgMembershipInput
type GetUserDetailInput = service.GetUserDetailInput
type LeaveOrgInput = service.LeaveOrgInput
type ListInvitesInput = service.ListInvitesInput
type ListMembersInput = service.ListMembersInput
type ListMembersResult = service.ListMembersResult
type ListOrgInvitesInput = service.ListOrgInvitesInput
type ListOrgInvitesResult = service.ListOrgInvitesResult
type ListSessionsResult = service.ListSessionsResult
type ListUserOrgsInput = service.ListUserOrgsInput
type ListUserOrgsResult = service.ListUserOrgsResult
type LoginActivityInput = service.LoginActivityInput
type LoginInput = service.LoginInput
type LoginResult = service.LoginResult
type OAuthCallbackResult = service.OAuthCallbackResult
type RegisterInput = service.RegisterInput
type RegisterResult = service.RegisterResult
type RemoveMemberInput = service.RemoveMemberInput
type ResetPasswordInput = service.ResetPasswordInput
type RevokeUserSessionInput = service.RevokeUserSessionInput
type RevokeUserSessionsInput = service.RevokeUserSessionsInput
type SessionResult = service.SessionResult
type SetActiveOrgInput = service.SetActiveOrgInput
type StatsRangeInput = service.StatsRangeInput
type TwoFactorVerifyResult = service.TwoFactorVerifyResult
type UnbanUserInput = service.UnbanUserInput
type UpdateMemberRoleInput = service.UpdateMemberRoleInput
type UpdateOrgInput = service.UpdateOrgInput
type UpdateUserRoleInput = service.UpdateUserRoleInput
type VerificationResult = service.VerificationResult
