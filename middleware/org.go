package middleware

import (
	"context"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/httperr"
	"github.com/nazimdjebloun/go-auth/port"
)

const (
	orgIDKey   ctxKey = "org_id"
	orgRoleKey ctxKey = "org_role"
)

func GetOrgID(ctx context.Context) string {
	v, _ := ctx.Value(orgIDKey).(string)
	return v
}

func GetOrgRole(ctx context.Context) domain.OrgRole {
	v, _ := ctx.Value(orgRoleKey).(domain.OrgRole)
	return v
}

// writeAuthError writes err's Code/Message as the standard
// {"error","message"} JSON envelope, with httperr.StatusFor(err.Code) as the
// status — matching what internal/handler's writeError produces for the same
// *domain.AuthError — callers reaching this package's org middleware and
// callers reaching the service directly (which returns these same sentinels
// from OrgService.requireRole) must see identical responses for identical
// failures.
func writeAuthError(w http.ResponseWriter, err *domain.AuthError) {
	writeJSON(w, httperr.StatusFor(err.Code), map[string]string{
		"error":   err.Code,
		"message": err.Message,
	}, nil)
}

func RequireOrgMember(orgs port.OrgRepository, userKeyFn func(context.Context) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID := r.PathValue("orgID")
			if orgID == "" {
				orgID = r.URL.Query().Get("org_id")
			}
			if orgID == "" {
				writeAuthError(w, domain.NewError("invalid_input", "orgID is required"))
				return
			}

			userID := userKeyFn(r.Context())
			if userID == "" {
				writeAuthError(w, domain.NewError("unauthorized", "Authentication required"))
				return
			}

			member, err := orgs.GetMembership(r.Context(), orgID, userID)
			if err != nil {
				// A repository failure is a server-side problem, not proof the
				// user isn't a member — never conflate the two into a 404.
				writeAuthError(w, domain.ErrInternal)
				return
			}
			if member == nil {
				writeAuthError(w, domain.ErrOrgMemberNotFound)
				return
			}

			ctx := context.WithValue(r.Context(), orgIDKey, orgID)
			ctx = context.WithValue(ctx, orgRoleKey, member.Role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireOrgRole(minRole domain.OrgRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := GetOrgRole(r.Context())
			if role.Weight() < minRole.Weight() {
				writeAuthError(w, domain.ErrOrgForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireActiveOrg requires the authenticated session to have an active org
// (set via SetActiveOrg), with a role at least minRole — for routes that
// operate implicitly on "the org I'm currently working in" rather than one
// named by an {orgID} path segment. Must run after AuthMiddleware, which is
// what puts the session in context.
//
// On success it stores the active org's ID and role in context under the
// same keys RequireOrgMember uses, so GetOrgID/GetOrgRole read back
// identically regardless of which of the two resolved the org.
func RequireActiveOrg(minRole domain.OrgRole) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session := GetSessionFromContext(r.Context())
			if session == nil || session.ActiveOrgID == nil || session.ActiveOrgRole == nil {
				writeAuthError(w, domain.ErrNoActiveOrg)
				return
			}
			role := domain.OrgRole(*session.ActiveOrgRole)
			if role.Weight() < minRole.Weight() {
				writeAuthError(w, domain.ErrOrgForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), orgIDKey, *session.ActiveOrgID)
			ctx = context.WithValue(ctx, orgRoleKey, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
