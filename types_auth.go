package goauth

import (
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
)

// ChallengeResult is an alias for service.ChallengeResult.
type ChallengeResult = service.ChallengeResult

// ChangePasswordInput is an alias for service.ChangePasswordInput.
type ChangePasswordInput = service.ChangePasswordInput

// ConfirmDeleteAccountInput is an alias for service.ConfirmDeleteAccountInput.
type ConfirmDeleteAccountInput = service.ConfirmDeleteAccountInput

// ConfirmSetPasswordInput is an alias for service.ConfirmSetPasswordInput.
type ConfirmSetPasswordInput = service.ConfirmSetPasswordInput

// EmailData is an alias for service.EmailData.
type EmailData = service.EmailData

// ForgotPasswordInput is an alias for service.ForgotPasswordInput.
type ForgotPasswordInput = service.ForgotPasswordInput

// ListSessionsResult is an alias for service.ListSessionsResult.
type ListSessionsResult = service.ListSessionsResult

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

// ResetPasswordInput is an alias for service.ResetPasswordInput.
type ResetPasswordInput = service.ResetPasswordInput

// SessionResult is an alias for domain.SessionResult.
type SessionResult = domain.SessionResult

// TwoFactorVerifyResult is an alias for service.TwoFactorVerifyResult.
type TwoFactorVerifyResult = service.TwoFactorVerifyResult

// VerificationResult is an alias for service.VerificationResult.
type VerificationResult = service.VerificationResult

// IsSessionError reports whether err is a session lookup failure
// (not found or expired), including wrapped values. Alias for the service
// implementation — the service package is internal and cannot be imported
// from another module, so this is the name external callers use.
var IsSessionError = service.IsSessionError
