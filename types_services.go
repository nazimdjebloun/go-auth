package goauth

import "github.com/nazimdjebloun/go-auth/internal/service"

// The service layer lives under internal/, so NewConfig(With...) is the only
// way to build a go-auth instance — the ten New*Service constructors and the
// configs they take are no longer reachable from outside this module.
//
// Its types still appear wherever a consumer actually works: the inputs and
// results of Auth.Register, Auth.Login, and every method on Auth.Services().
// These aliases keep all of that nameable, so a consumer can declare a
// variable, a struct field, or a function signature for any of it. They are
// aliases, not wrappers — goauth.RegisterInput and the service's own type are
// the same type, so there is no conversion and nothing to drift.

// AdminService is an alias for service.AdminService.
type AdminService = service.AdminService

// AuthService is an alias for service.AuthService.
type AuthService = service.AuthService

// InviteService is an alias for service.InviteService.
type InviteService = service.InviteService

// OAuthService is an alias for service.OAuthService.
type OAuthService = service.OAuthService

// OrgInviteService is an alias for service.OrgInviteService.
type OrgInviteService = service.OrgInviteService

// OrgService is an alias for service.OrgService.
type OrgService = service.OrgService

// PasswordService is an alias for service.PasswordService.
type PasswordService = service.PasswordService

// SessionService is an alias for service.SessionService.
type SessionService = service.SessionService

// TwoFactorService is an alias for service.TwoFactorService.
type TwoFactorService = service.TwoFactorService

// VerificationService is an alias for service.VerificationService.
type VerificationService = service.VerificationService
