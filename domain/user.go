package domain

import "time"

// Role identifies legacy account access when app permissions are disabled.
type Role string

// RoleUser and RoleAdmin are the supported account roles.
const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

// User holds account identity, status, and authentication metadata.
type User struct {
	ID                    string  `json:"id"`
	Email                 string  `json:"email"`
	PasswordHash          *string `json:"-"`
	PasswordPepperVersion *uint32 `json:"-"`
	Name                  string  `json:"name"`
	// Role is populated only when app permissions are disabled.
	Role Role `json:"role,omitempty"`
	// AppRoleID is authoritative when WithAppPermissions is enabled. Role is
	// omitted in enabled-mode results; it is not a second grant source.
	AppRoleID                 *string    `json:"appRoleId,omitempty"`
	AppRoleAssignmentRevision uint64     `json:"appRoleAssignmentRevision,omitempty"`
	IsVerified                bool       `json:"isVerified"`
	VerifiedAt                *time.Time `json:"verifiedAt,omitempty"`
	IsBanned                  bool       `json:"isBanned"`
	BannedAt                  *time.Time `json:"bannedAt,omitempty"`
	TwoFactorEnabled          bool       `json:"twoFactorEnabled"`
	LastLoginAt               *time.Time `json:"lastLoginAt,omitempty"`
	OrgOwnerCount             int        `json:"orgOwnerCount"`
	CreatedAt                 time.Time  `json:"createdAt"`
	UpdatedAt                 time.Time  `json:"updatedAt"`
}

// HasPassword reports whether the user has a password login method.
func (u *User) HasPassword() bool {
	return u.PasswordHash != nil
}

// TokenType identifies the workflow that issued a verification token.
type TokenType string

// TokenVerifyEmail and the following values are supported token types.
const (
	TokenVerifyEmail   TokenType = "verify_email"
	TokenResetPass     TokenType = "reset_password"
	TokenSetPass       TokenType = "set_password"
	TokenInviteVerify  TokenType = "invite_verify"
	TokenOAuthState    TokenType = "oauth_" + "state"
	TokenDeleteAccount TokenType = "delete_account"
	TokenTwoFactor     TokenType = "2fa_login"
)

// VerificationToken records a hashed, expiring workflow token.
type VerificationToken struct {
	ID           string     `json:"id"`
	UserID       *string    `json:"userId,omitempty"` // nil for invite verify codes
	Email        string     `json:"email"`
	TokenHash    string     `json:"-"`
	Type         TokenType  `json:"type"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	UsedAt       *time.Time `json:"usedAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	CodeVerifier *string    `json:"-"` // PKCE code verifier for OAuth state tokens

	// Attempts and ResendCount are per-token (per challenge lineage) counters
	// used by the 2FA login flow. They stay on this row across a resend, which
	// is what stops a resend from handing out a fresh guess budget.
	Attempts    int `json:"-"`
	ResendCount int `json:"-"`
}

// InviteStatus identifies the lifecycle state of a platform invite.
type InviteStatus string

// InvitePending and the following values are valid invite states.
const (
	InvitePending  InviteStatus = "pending"
	InviteAccepted InviteStatus = "accepted"
	InviteRevoked  InviteStatus = "revoked"
	InviteExpired  InviteStatus = "expired"
)

// Invite records an invitation to create an account.
type Invite struct {
	ID         string       `json:"id"`
	Email      string       `json:"email"`
	Code       string       `json:"-"`                 // sha256 hash, never exposed
	RawCode    string       `json:"rawCode,omitempty"` // populated once on creation, omitted in list
	CreatedBy  string       `json:"createdBy"`
	Status     InviteStatus `json:"status"`
	ExpiresAt  time.Time    `json:"expiresAt"`
	AcceptedAt *time.Time   `json:"acceptedAt,omitempty"`
	CreatedAt  time.Time    `json:"createdAt"`
}
