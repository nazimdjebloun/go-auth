// Package middleware provides the net/http middleware go-auth's built-in
// routes are wrapped in (auth.go's Mount), and exposes the same pieces for
// protecting a consumer's own routes via Auth.RequireAuth, Auth.RequireAdmin,
// Auth.RequireOrg, Auth.RateLimit, and Auth.CORS.
//
// AuthMiddleware validates the session cookie (transparently refreshing an
// expired session via the refresh cookie when possible) and places the
// authenticated user and session in the request context — read them back
// with GetUserFromContext and GetSessionFromContext. RequireRole and
// RequireOrgRole layer a role check on top, reading the same context.
//
// This package requires net/http.ServeMux-style routing: RequireOrgMember
// resolves the org ID from r.PathValue("orgID") (falling back to the
// org_id query parameter), which only ServeMux populates from a route
// pattern like "GET /auth/orgs/{orgID}". See Auth.Mount's doc comment for
// the same constraint on the built-in routes.
package middleware
