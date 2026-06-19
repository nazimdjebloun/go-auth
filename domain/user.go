package domain

import "time"

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type User struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	Name         string     `json:"name"`
	Role         Role       `json:"role"`
	IsVerified   bool       `json:"isVerified"`
	IsBanned     bool       `json:"isBanned"`
	BannedAt     *time.Time `json:"bannedAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

type TokenType string

const (
	TokenVerifyEmail TokenType = "verify_email"
	TokenResetPass   TokenType = "reset_password"
	TokenInviteVerify TokenType = "invite_verify"
)

type VerificationToken struct {
	ID        string     `json:"id"`
	UserID    *string    `json:"userId,omitempty"` // nil for invite verify codes
	Email     string     `json:"email"`
	TokenHash string     `json:"-"`
	Type      TokenType  `json:"type"`
	ExpiresAt time.Time  `json:"expiresAt"`
	UsedAt    *time.Time `json:"usedAt,omitempty"`
}

type InviteStatus string

const (
	InvitePending  InviteStatus = "pending"
	InviteAccepted InviteStatus = "accepted"
	InviteRevoked  InviteStatus = "revoked"
	InviteExpired  InviteStatus = "expired"
)

type Invite struct {
	ID         string       `json:"id"`
	Email      string       `json:"email"`
	Code       string       `json:"-"`            // sha256 hash, never exposed
	RawCode    string       `json:"rawCode,omitempty"` // populated once on creation, omitted in list
	CreatedBy  string       `json:"createdBy"`
	Status     InviteStatus `json:"status"`
	ExpiresAt  time.Time    `json:"expiresAt"`
	AcceptedAt *time.Time   `json:"acceptedAt,omitempty"`
	CreatedAt  time.Time    `json:"createdAt"`
}
