package domain

import "net/http"

type AuthError struct {
	Code       string `json:"error"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"-"`
}

func (e *AuthError) Error() string {
	return e.Code + ": " + e.Message
}

func NewError(code string, msg string, status int) *AuthError {
	return &AuthError{Code: code, Message: msg, HTTPStatus: status}
}

var (
	ErrEmailAlreadyExists       = NewError("email_already_exists", "An account with this email already exists", http.StatusConflict)
	ErrInvalidCredentials       = NewError("invalid_credentials", "Invalid email or password", http.StatusUnauthorized)
	ErrUserBanned               = NewError("user_banned", "This account has been banned", http.StatusForbidden)
	ErrEmailNotVerified         = NewError("email_not_verified", "Please verify your email first", http.StatusForbidden)
	ErrWeakPassword             = NewError("weak_password", "Password must be at least 8 characters", http.StatusBadRequest)
	ErrInvalidEmail             = NewError("invalid_email", "Invalid email format", http.StatusBadRequest)
	ErrUserNotFound             = NewError("user_not_found", "User not found", http.StatusNotFound)
	ErrForbidden                = NewError("forbidden", "You do not have permission", http.StatusForbidden)
	ErrResetTokenExpired        = NewError("reset_token_expired", "Password reset token has expired", http.StatusGone)
	ErrResetTokenInvalid        = NewError("reset_token_invalid", "Invalid password reset token", http.StatusBadRequest)
	ErrResetTokenAlreadyUsed    = NewError("reset_token_already_used", "Password reset token has already been used", http.StatusGone)
	ErrInviteNotFound           = NewError("invite_not_found", "Invite not found", http.StatusNotFound)
	ErrInviteExpired            = NewError("invite_expired", "This invite has expired", http.StatusGone)
	ErrInviteAlreadyUsed        = NewError("invite_already_used", "This invite has already been used", http.StatusGone)
	ErrInviteRevoked            = NewError("invite_revoked", "This invite has been revoked", http.StatusForbidden)
	ErrRateLimitExceeded        = NewError("rate_limit_exceeded", "Too many requests, please try again later", http.StatusTooManyRequests)
	ErrAccountAlreadyExists     = NewError("account_already_exists", "An account with this email already exists", http.StatusConflict)
	ErrSessionNotFound          = NewError("session_not_found", "Session not found", http.StatusNotFound)
	ErrSessionExpired           = NewError("session_expired", "Session has expired", http.StatusUnauthorized)
	ErrSessionRevoked           = NewError("session_revoked", "Session has been revoked", http.StatusUnauthorized)
	ErrInvalidRefreshToken      = NewError("invalid_refresh_token", "Refresh token is invalid", http.StatusUnauthorized)
	ErrRefreshExpired           = NewError("refresh_expired", "Refresh token has expired", http.StatusUnauthorized)
	ErrTokenAlreadyRotated      = NewError("token_already_rotated", "This refresh token has already been rotated — use the new one", http.StatusConflict)
	ErrMaxLifetimeExceeded      = NewError("max_lifetime_exceeded", "Session lifetime exceeded, please re-authenticate", http.StatusUnauthorized)
	ErrProviderNotFound         = NewError("provider_not_found", "Unrecognized provider", http.StatusNotFound)
	ErrProviderEmailUnverified  = NewError("provider_email_unverified", "Provider email is not verified", http.StatusForbidden)
	ErrProviderAccountExists    = NewError("provider_already_linked", "This provider is already linked to another account", http.StatusConflict)
	ErrProviderAccountNotFound  = NewError("provider_not_linked", "This provider is not linked to your account", http.StatusNotFound)
	ErrCannotUnlinkLastProvider = NewError("cannot_unlink_last_provider", "Cannot unlink last login method — set a password first", http.StatusBadRequest)
	ErrDeleteCodeInvalid        = NewError("delete_code_invalid", "Invalid deletion code", http.StatusBadRequest)
	ErrDeleteCodeExpired        = NewError("delete_code_expired", "Deletion code has expired", http.StatusGone)
	ErrDeleteCodeAlreadyUsed    = NewError("delete_code_already_used", "Deletion code has already been used", http.StatusGone)
	ErrPasswordRequired         = NewError("password_required", "Password is required to delete account", http.StatusBadRequest)
	ErrOrgNotFound              = NewError("org_not_found", "Organization not found", http.StatusNotFound)
	ErrOrgSlugExists            = NewError("org_slug_exists", "Organization slug already in use", http.StatusConflict)
	ErrOrgSlugReserved          = NewError("org_slug_reserved", "Organization slug is reserved", http.StatusBadRequest)
	ErrOrgMemberNotFound        = NewError("org_member_not_found", "User is not a member of this organization", http.StatusNotFound)
	ErrOrgMemberExists          = NewError("org_member_exists", "User is already a member of this organization", http.StatusConflict)
	ErrCannotRemoveLastOwner    = NewError("cannot_remove_last_owner", "Cannot remove or demote the last owner of an organization", http.StatusBadRequest)
	ErrOrgLimitReached          = NewError("org_limit_reached", "Maximum organization limit reached for user", http.StatusBadRequest)
	ErrOrgMemberLimitReached    = NewError("org_member_limit_reached", "Organization member limit reached", http.StatusBadRequest)
	ErrOrgForbidden             = NewError("org_forbidden", "Insufficient organization permissions", http.StatusForbidden)
	ErrOrgInviteExpired         = NewError("org_invite_expired", "Organization invite link has expired", http.StatusBadRequest)
	ErrOrgInviteEmailMismatch   = NewError("org_invite_email_mismatch", "Authenticated email does not match invite recipient", http.StatusBadRequest)
	ErrOrgMetadataTooLarge      = NewError("org_metadata_too_large", "Organization metadata exceeds 16KB limit", http.StatusBadRequest)
	ErrMethodDisabled           = NewError("method_disabled", "This registration method is not available", http.StatusMethodNotAllowed)

	ErrTwoFactorCodeInvalid     = NewError("two_factor_code_invalid", "Invalid two-factor code", http.StatusBadRequest)
	ErrTwoFactorCodeExpired     = NewError("two_factor_code_expired", "Two-factor code has expired", http.StatusGone)
	ErrTwoFactorCodeAlreadyUsed = NewError("two_factor_code_already_used", "This two-factor code has already been used", http.StatusGone)
	ErrTwoFactorAlreadyEnforced = NewError("two_factor_already_enforced", "Two-factor authentication is required and cannot be changed", http.StatusConflict)
	// Deliberately not ErrPasswordRequired: that one's message is specific to
	// account deletion, and generalizing it would change that response body.
	// The code must differ too, not just the variable — "password_required" is
	// ErrPasswordRequired's code, and a shared code means a client matching on
	// err.Code can't tell the two apart even though the messages differ.
	ErrTwoFactorPasswordRequired = NewError("two_factor_password_required", "Password is required to change two-factor settings", http.StatusBadRequest)
)
