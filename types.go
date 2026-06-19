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

type VerifyInviteInput struct {
	Email string
	Code  string
}

type CompleteInviteInput struct {
	Email            string
	VerificationCode string
	Password         string
	Name             string
}

type CompleteInviteResult struct {
	User         *domain.User
	Session      *domain.Session
	SessionToken string
}
