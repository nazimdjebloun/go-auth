package middleware

import (
	"context"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
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

// writeAuthError writes err's Code/Message/HTTPStatus as the standard
// {"error","message"} JSON envelope, matching what internal/handler's
// writeError produces for the same *domain.AuthError — callers reaching this
// package's org middleware and callers reaching the service directly (which
// returns these same sentinels from OrgService.requireRole) must see
// identical responses for identical failures.
func writeAuthError(w http.ResponseWriter, err *domain.AuthError) {
	writeJSON(w, err.HTTPStatus, map[string]string{
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
				writeAuthError(w, domain.NewError("invalid_input", "orgID is required", http.StatusBadRequest))
				return
			}

			userID := userKeyFn(r.Context())
			if userID == "" {
				writeAuthError(w, domain.NewError("unauthorized", "Authentication required", http.StatusUnauthorized))
				return
			}

			member, err := orgs.GetMembership(r.Context(), orgID, userID)
			if err != nil {
				// A repository failure is a server-side problem, not proof the
				// user isn't a member — never conflate the two into a 404.
				writeAuthError(w, domain.NewError("internal_error", "Internal server error", http.StatusInternalServerError))
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
