// Package sessioncontext identifies independent browser credential contexts.
// Context labels are selectors, never authorization claims.
package sessioncontext

import (
	"context"
	"strings"
)

// Scope identifies a browser credential context.
type Scope string

// App and Admin are the supported contexts; Header selects one in HTTP.
const (
	App         Scope = "app"
	Admin       Scope = "admin"
	Header            = "X-GoAuth-Session"
	adminPrefix       = "ga-admin."
)

type key struct{}

// With records a validated context selection.
func With(ctx context.Context, scope Scope) context.Context {
	return context.WithValue(ctx, key{}, scope)
}

// Current returns the selected context, defaulting to App.
func Current(ctx context.Context) Scope {
	if scope, ok := ctx.Value(key{}).(Scope); ok {
		return scope
	}
	return App
}

// Explicit reports whether an HTTP context has been selected.
func Explicit(ctx context.Context) bool { _, ok := ctx.Value(key{}).(Scope); return ok }

// Of classifies an opaque credential. Its full value, including this label,
// is hashed at rest: editing the label cannot relabel a stored credential.
func Of(value string) Scope {
	if strings.HasPrefix(value, adminPrefix) {
		return Admin
	}
	return App
}

// Bind qualifies random credentials before their complete value is hashed.
func Bind(scope Scope, value string) string {
	if scope == Admin {
		return adminPrefix + value
	}
	if strings.HasPrefix(value, adminPrefix) {
		return "ga-app." + value
	}
	return value
}

// Matches constrains HTTP requests. Programmatic services may validate either
// context when no browser context has been selected.
func Matches(ctx context.Context, value string) bool {
	return !Explicit(ctx) || Current(ctx) == Of(value)
}
