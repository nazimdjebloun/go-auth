package middleware

import (
	"context"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type contextKey string

const (
	orgIDKey   contextKey = "org_id"
	orgRoleKey contextKey = "org_role"
)

func GetOrgID(ctx context.Context) string {
	v, _ := ctx.Value(orgIDKey).(string)
	return v
}

func GetOrgRole(ctx context.Context) domain.OrgRole {
	v, _ := ctx.Value(orgRoleKey).(domain.OrgRole)
	return v
}

func RequireOrgMember(orgs port.OrgRepository, userKeyFn func(context.Context) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			orgID := r.PathValue("orgID")
			if orgID == "" {
				orgID = r.URL.Query().Get("org_id")
			}
			if orgID == "" {
				http.Error(w, `{"error":"org_id required"}`, http.StatusBadRequest)
				return
			}

			userID := userKeyFn(r.Context())
			if userID == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			member, err := orgs.GetMembership(r.Context(), orgID, userID)
			if err != nil || member == nil {
				http.Error(w, `{"error":"not an org member"}`, http.StatusForbidden)
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
				http.Error(w, `{"error":"insufficient role"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
