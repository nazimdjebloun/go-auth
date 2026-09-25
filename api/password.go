package api

// ChangePasswordInput contains a user's current and new passwords.
type ChangePasswordInput struct {
	UserID          string
	OldPassword     string
	NewPassword     string
	ExceptSessionID string
}

// ConfirmDeleteAccountInput contains an account-deletion code.
type ConfirmDeleteAccountInput struct {
	UserID string
	Code   string
}

// ConfirmSetPasswordInput contains a setup code and new password.
type ConfirmSetPasswordInput struct {
	UserID      string
	Code        string
	NewPassword string
}

// ForgotPasswordInput identifies the account requesting a password reset.
type ForgotPasswordInput struct {
	Email string
}

// ResetPasswordInput contains a reset code and new password.
type ResetPasswordInput struct {
	Code        string
	NewPassword string
}
