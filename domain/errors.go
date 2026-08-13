package domain

type AuthError struct {
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *AuthError) Error() string {
	return e.Code + ": " + e.Message
}

// Is makes errors.Is(err, domain.ErrXxx) match by Code rather than pointer
// identity. Without it, an *AuthError built inline with the same code as one
// of the sentinels below (domain.NewError("session_not_found", ...) instead
// of reusing domain.ErrSessionNotFound) would never compare equal, even
// though it represents the same error.
func (e *AuthError) Is(target error) bool {
	t, ok := target.(*AuthError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

func NewError(code string, msg string) *AuthError {
	return &AuthError{Code: code, Message: msg}
}

var (
	ErrInternal                 = NewError("internal_error", "Internal server error")
	ErrEmailAlreadyExists       = NewError("email_already_exists", "An account with this email already exists")
	ErrInvalidCredentials       = NewError("invalid_credentials", "Invalid email or password")
	ErrUserBanned               = NewError("user_banned", "This account has been banned")
	ErrEmailNotVerified         = NewError("email_not_verified", "Please verify your email first")
	ErrWeakPassword             = NewError("weak_password", "Password must be at least 8 characters")
	ErrInvalidEmail             = NewError("invalid_email", "Invalid email format")
	ErrUserNotFound             = NewError("user_not_found", "User not found")
	ErrForbidden                = NewError("forbidden", "You do not have permission")
	ErrResetTokenExpired        = NewError("reset_token_expired", "Password reset token has expired")
	ErrResetTokenInvalid        = NewError("reset_token_invalid", "Invalid password reset token")
	ErrResetTokenAlreadyUsed    = NewError("reset_token_already_used", "Password reset token has already been used")
	ErrInviteNotFound           = NewError("invite_not_found", "Invite not found")
	ErrInviteExpired            = NewError("invite_expired", "This invite has expired")
	ErrInviteAlreadyUsed        = NewError("invite_already_used", "This invite has already been used")
	ErrInviteRevoked            = NewError("invite_revoked", "This invite has been revoked")
	ErrRateLimitExceeded        = NewError("rate_limit_exceeded", "Too many requests, please try again later")
	ErrAccountAlreadyExists     = NewError("account_already_exists", "An account with this email already exists")
	ErrSessionNotFound          = NewError("session_not_found", "Session not found")
	ErrSessionExpired           = NewError("session_expired", "Session has expired")
	ErrSessionRevoked           = NewError("session_revoked", "Session has been revoked")
	ErrInvalidRefreshToken      = NewError("invalid_refresh_token", "Refresh token is invalid")
	ErrRefreshExpired           = NewError("refresh_expired", "Refresh token has expired")
	ErrTokenAlreadyRotated      = NewError("token_already_rotated", "This refresh token has already been rotated — use the new one")
	ErrMaxLifetimeExceeded      = NewError("max_lifetime_exceeded", "Session lifetime exceeded, please re-authenticate")
	ErrProviderNotFound         = NewError("provider_not_found", "Unrecognized provider")
	ErrProviderAccountExists    = NewError("provider_already_linked", "This provider is already linked to another account")
	ErrProviderAccountNotFound  = NewError("provider_not_linked", "This provider is not linked to your account")
	ErrCannotUnlinkLastProvider = NewError("cannot_unlink_last_provider", "Cannot unlink last login method — set a password first")
	ErrDeleteCodeInvalid        = NewError("delete_code_invalid", "Invalid deletion code")
	ErrDeleteCodeExpired        = NewError("delete_code_expired", "Deletion code has expired")
	ErrDeleteCodeAlreadyUsed    = NewError("delete_code_already_used", "Deletion code has already been used")
	ErrPasswordRequired         = NewError("password_required", "Password is required to delete account")
	ErrOrgNotFound              = NewError("org_not_found", "Organization not found")
	ErrOrgSlugExists            = NewError("org_slug_exists", "Organization slug already in use")
	ErrOrgSlugReserved          = NewError("org_slug_reserved", "Organization slug is reserved")
	ErrOrgMemberNotFound        = NewError("org_member_not_found", "User is not a member of this organization")
	ErrOrgMemberExists          = NewError("org_member_exists", "User is already a member of this organization")
	ErrCannotRemoveLastOwner    = NewError("cannot_remove_last_owner", "Cannot remove or demote the last owner of an organization")
	ErrOrgLimitReached          = NewError("org_limit_reached", "Maximum organization limit reached for user")
	ErrOrgMemberLimitReached    = NewError("org_member_limit_reached", "Organization member limit reached")
	ErrOrgForbidden             = NewError("org_forbidden", "Insufficient organization permissions")
	ErrOrgInviteExpired         = NewError("org_invite_expired", "Organization invite link has expired")
	ErrOrgInviteEmailMismatch   = NewError("org_invite_email_mismatch", "Authenticated email does not match invite recipient")
	ErrOrgMetadataTooLarge      = NewError("org_metadata_too_large", "Organization metadata exceeds 16KB limit")
	ErrMethodDisabled           = NewError("method_disabled", "This registration method is not available")

	ErrTwoFactorCodeInvalid     = NewError("two_factor_code_invalid", "Invalid two-factor code")
	ErrTwoFactorCodeExpired     = NewError("two_factor_code_expired", "Two-factor code has expired")
	ErrTwoFactorCodeAlreadyUsed = NewError("two_factor_code_already_used", "This two-factor code has already been used")
	ErrTwoFactorAlreadyEnforced = NewError("two_factor_already_enforced", "Two-factor authentication is required and cannot be changed")
	// Deliberately not ErrPasswordRequired: that one's message is specific to
	// account deletion, and generalizing it would change that response body.
	// The code must differ too, not just the variable — "password_required" is
	// ErrPasswordRequired's code, and a shared code means a client matching on
	// err.Code can't tell the two apart even though the messages differ.
	ErrTwoFactorPasswordRequired = NewError("two_factor_password_required", "Password is required to change two-factor settings")
)
