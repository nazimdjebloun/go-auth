package middleware

import (
	"context"
	"net/http"
	"reflect"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// OrgPermissionChecker evaluates a current membership, role, definition and grant.
// Allowed decisions must include the resolved fixed MembershipRole.
type OrgPermissionChecker interface {
	CheckPermission(context.Context, api.CheckOrgPermissionInput) (*api.OrgPermissionDecision, error)
}

// RequireOrgPermission resolves the org from the path, then authorized context.
// Authentication must run first. No session role snapshot grants access.
// Successful checks store both the organization ID and live membership role.
func RequireOrgPermission(checker OrgPermissionChecker, key string) func(http.Handler) http.Handler {
	return requireOrgPermission(checker, key, false)
}

// RequireActiveOrgPermission resolves only the org ID from the current session.
func RequireActiveOrgPermission(checker OrgPermissionChecker, key string) func(http.Handler) http.Handler {
	return requireOrgPermission(checker, key, true)
}

func requireOrgPermission(checker OrgPermissionChecker, key string, active bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil || (reflect.ValueOf(checker).Kind() == reflect.Pointer && reflect.ValueOf(checker).IsNil()) {
				writeAppAuthorizationError(w, domain.ErrOrgPermissionsDisabled)
				return
			}
			user := GetUserFromContext(r.Context())
			if user == nil {
				writeAppAuthorizationError(w, domain.ErrForbidden)
				return
			}
			actor := api.OrgPermissionActor{UserID: user.ID, OrgID: r.PathValue("orgID")}
			session := GetSessionFromContext(r.Context())
			if session != nil {
				actor.SessionID = session.ID
			}
			if active {
				if session == nil || session.ActiveOrgID == nil {
					writeAppAuthorizationError(w, domain.ErrNoActiveOrg)
					return
				}
				actor.OrgID = *session.ActiveOrgID
			} else if actor.OrgID == "" {
				actor.OrgID = GetOrgID(r.Context())
			}
			decision, err := checker.CheckPermission(r.Context(), api.CheckOrgPermissionInput{Actor: actor, PermissionKey: key})
			if err != nil {
				writeAppAuthorizationError(w, err)
				return
			}
			if decision == nil || !decision.Allowed {
				writeAppAuthorizationError(w, domain.ErrOrgForbidden)
				return
			}
			if actor.OrgID == "" || !decision.MembershipRole.IsValid() {
				writeAppAuthorizationError(w, domain.ErrInternal)
				return
			}
			ctx := context.WithValue(r.Context(), orgIDKey, actor.OrgID)
			ctx = context.WithValue(ctx, orgRoleKey, decision.MembershipRole)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
