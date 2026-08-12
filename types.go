package goauth

import "github.com/nazimdjebloun/go-auth/service"

// RegisterInput, LoginInput, and CompleteInviteInput are aliases of the
// same-named service types, not separate structs — the root API and the
// service layer share one input/result shape per operation instead of two
// near-duplicates that could drift out of sync (previously RegisterInput
// had no IP/UserAgent fields at all, so Auth.Register silently dropped
// them from audit events and session records for programmatic callers).
// Aliasing also surfaces the 2FA-challenge result fields (RequiresTwoFactor,
// CodeSent, TwoFactorChallenge, TwoFactorExpiresAt, BindingToken()) on the
// programmatic API, matching what the HTTP handlers already return.
type RegisterInput = service.RegisterInput
type RegisterResult = service.RegisterResult
type LoginInput = service.LoginInput
type LoginResult = service.LoginResult
type CompleteInviteInput = service.CompleteInviteInput
type CompleteInviteResult = service.CompleteInviteResult
