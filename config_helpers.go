package goauth

import "time"

// Pointer helpers for the config fields whose zero value is a real setting,
// so "unset" needs a third state. Each returns a pointer the caller can hand
// straight to a With* option.

// Duration returns a pointer to d, for SessionConfig.GraceWindow and
// SessionConfig.TouchDebounce — Go can't take the address of a duration
// literal directly. Both fields are *time.Duration rather than
// time.Duration specifically so 0 can mean "explicitly off" without
// colliding with "left unset, use the default": leave the field nil for
// the default, or set it with goauth.Duration(0) to turn the feature off,
// goauth.Duration(10*time.Second) for a custom value, and so on.
func Duration(d time.Duration) *time.Duration { return &d }

// boolPtr returns a pointer to v — the shared implementation behind the
// readable spellings below, for the tri-state config fields where nil means
// "derive from the environment": CookieConfig.Secure and
// SecurityConfig.AllowHTTPURLs.
func boolPtr(v bool) *bool { return &v }

// SecureAlways and SecureNever are readable spellings for CookieConfig.Secure.
// SecureNever is for local development over http:// only — browsers will send
// the cookie over plaintext connections.
func SecureAlways() *bool { return boolPtr(true) }
func SecureNever() *bool  { return boolPtr(false) }

// AllowPlaintextEmailLinks and RequireHTTPSEmailLinks are readable spellings
// for SecurityConfig.AllowHTTPURLs. AllowPlaintextEmailLinks permits http://
// links in emails outside a dev environment; RequireHTTPSEmailLinks enforces
// https:// even inside one.
func AllowPlaintextEmailLinks() *bool { return boolPtr(true) }
func RequireHTTPSEmailLinks() *bool   { return boolPtr(false) }
