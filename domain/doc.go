// Package domain holds go-auth's core types — User, Session, Organization,
// Invite, ProviderAccount, and their supporting enums — plus AuthError, the
// single error type every public method returns.
//
// AuthError carries a stable Code (safe to match on — see AuthError.Is),
// a user-facing Message, and the HTTPStatus the HTTP layer maps it to. The
// sentinel Err* variables in errors.go are pre-built AuthErrors for common
// conditions (ErrUserNotFound, ErrSessionExpired, ...); compare against them
// with errors.Is, not equality, since a wrapped or independently-constructed
// AuthError with the same Code is still the same logical error.
package domain
