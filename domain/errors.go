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
	ErrEmailAlreadyExists  = NewError("email_already_exists", "An account with this email already exists", http.StatusConflict)
	ErrInvalidCredentials  = NewError("invalid_credentials", "Invalid email or password", http.StatusUnauthorized)
	ErrUserBanned          = NewError("user_banned", "This account has been banned", http.StatusForbidden)
	ErrEmailNotVerified    = NewError("email_not_verified", "Please verify your email first", http.StatusForbidden)
	ErrWeakPassword        = NewError("weak_password", "Password must be at least 8 characters", http.StatusBadRequest)
	ErrInvalidEmail        = NewError("invalid_email", "Invalid email format", http.StatusBadRequest)
	ErrUserNotFound        = NewError("user_not_found", "User not found", http.StatusNotFound)
	ErrForbidden           = NewError("forbidden", "You do not have permission", http.StatusForbidden)
	ErrTokenExpired        = NewError("token_expired", "This token has expired", http.StatusGone)
	ErrTokenInvalid        = NewError("token_invalid", "Invalid token", http.StatusBadRequest)
	ErrTokenAlreadyUsed    = NewError("token_already_used", "This token has already been used", http.StatusGone)
	ErrInviteNotFound      = NewError("invite_not_found", "Invite not found", http.StatusNotFound)
	ErrInviteExpired       = NewError("invite_expired", "This invite has expired", http.StatusGone)
	ErrInviteAlreadyUsed   = NewError("invite_already_used", "This invite has already been used", http.StatusGone)
	ErrInviteRevoked       = NewError("invite_revoked", "This invite has been revoked", http.StatusForbidden)
	ErrRateLimitExceeded   = NewError("rate_limit_exceeded", "Too many requests, please try again later", http.StatusTooManyRequests)
	ErrAccountAlreadyExists = NewError("account_already_exists", "An account with this email already exists", http.StatusConflict)
	ErrSessionNotFound     = NewError("session_not_found", "Session not found", http.StatusNotFound)
	ErrSessionExpired      = NewError("session_expired", "Session has expired", http.StatusUnauthorized)
)
