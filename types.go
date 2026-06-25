package goauth

import "github.com/nazimdjebloun/go-auth/domain"

type RegisterInput struct {
	Email    string
	Password string
	Name     string
}

type RegisterResult struct {
	User         *domain.User
	Session      *domain.Session
	SessionToken string
	RefreshToken string
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
	RefreshToken string
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
	RefreshToken string
}
