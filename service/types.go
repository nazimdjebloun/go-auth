package service

import (
	"github.com/nazimdjebloun/go-auth/domain"
)

type RegisterInput struct {
	Email    string
	Password string
	Name     string
}

type RegisterResult struct {
	User         *domain.User
	Session      *domain.Session
	SessionToken string
}

type LoginInput struct {
	Email     string
	Password  string
	IP        string
	UserAgent string
}

type LoginResult struct {
	User         *domain.User
	Session      *domain.Session
	SessionToken string
}

type CompleteInviteInput struct {
	Code            string
	Name            string
	Password        string
	ConfirmPassword string
}

type CompleteInviteResult struct {
	User         *domain.User
	Session      *domain.Session
	SessionToken string
}

type ForgotPasswordInput struct {
	Email string
}

type ResetPasswordInput struct {
	Email      string
	Code       string
	NewPassword string
}

type ChangePasswordInput struct {
	UserID          string
	OldPassword     string
	NewPassword     string
	ExceptSessionID string
}

type ListSessionsResult struct {
	Sessions []domain.Session
}

type AdminListUsersInput struct {
	Offset         int
	Limit          int // 0 = unlimited
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
