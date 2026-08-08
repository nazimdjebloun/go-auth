package service

import (
	"github.com/nazimdjebloun/go-auth/domain"
)

type RegisterInput struct {
	Email     string
	Password  string
	Name      string
	IP        string
	UserAgent string
}

// RegisterResult is serialized directly by the HTTP handler on the normal
// success path. Tags keep it consistent with the hand-built map the handler
// uses on the requires-verification path ({"user", "requiresVerification",
// "message"}) — both used to produce the same field capitalized differently
// depending on which branch ran.
type RegisterResult struct {
	User                 *domain.User    `json:"user"`
	Session              *domain.Session `json:"session,omitempty"`
	SessionToken         string          `json:"sessionToken,omitempty"`
	RefreshToken         string          `json:"refreshToken,omitempty"`
	RequiresVerification bool            `json:"requiresVerification,omitempty"`
}

type LoginInput struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
}

// LoginResult has the same dual-shape rationale as RegisterResult above.
type LoginResult struct {
	User                 *domain.User    `json:"user"`
	Session              *domain.Session `json:"session,omitempty"`
	SessionToken         string          `json:"sessionToken,omitempty"`
	RefreshToken         string          `json:"refreshToken,omitempty"`
	RequiresVerification bool            `json:"requiresVerification,omitempty"`
}

type CompleteInviteInput struct {
	Code            string
	Name            string
	Password        string
	ConfirmPassword string
	IP              string
	UserAgent       string
}

type CompleteInviteResult struct {
	User         *domain.User    `json:"user"`
	Session      *domain.Session `json:"session,omitempty"`
	SessionToken string          `json:"sessionToken,omitempty"`
	RefreshToken string          `json:"refreshToken,omitempty"`
}

type ForgotPasswordInput struct {
	Email string
}

type ResetPasswordInput struct {
	Code        string
	NewPassword string
}

type ChangePasswordInput struct {
	UserID          string
	OldPassword     string
	NewPassword     string
	ExceptSessionID string
}

type ConfirmSetPasswordInput struct {
	UserID      string
	Code        string
	NewPassword string
}

type ListSessionsResult struct {
	Sessions []domain.Session
}

type AdminListUsersInput struct {
	Offset         int
	Limit          int // default 20, max 100
	Email          *string
	Role           *domain.Role
	Search         *string
	OrderBy        string // "created_at" or "updated_at"
	OrderDirection string // "asc" or "desc"
}

type AdminListUsersResult struct {
	Users  []domain.User `json:"users"`
	Total  int           `json:"total"`
	Limit  int           `json:"limit,omitempty"`
	Offset int           `json:"offset,omitempty"`
}

type ListInvitesInput struct {
	Offset int
	Limit  int
	Search string
	Status string
}

type CreateInviteInput struct {
	Email   string
	AdminID string
}

type EmailData struct {
	To      string
	Subject string
	HTML    string
	Text    string
}

type CreateUserInput struct {
	Email    string
	Password string
	Name     string
	Role     string
}

type AdminListUserSessionsInput struct {
	UserID string
	Offset int
	Limit  int
}

type ConfirmDeleteAccountInput struct {
	UserID string
	Code   string
}
