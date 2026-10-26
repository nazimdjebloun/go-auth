package middleware

import (
	"context"
	"net/http"
	"reflect"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// OrgPermissionChecker evaluates a current membership, role, definition and grant.
type OrgPermissionChecker interface {
	RequirePermission(context.Context, api.CheckOrgPermissionInput) error
}

// RequireOrgPermission resolves the org from the path, then authorized context.
// Authentication must run first. No session role snapshot grants access.
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
			if err := checker.RequirePermission(r.Context(), api.CheckOrgPermissionInput{Actor: actor, PermissionKey: key}); err != nil {
				writeAppAuthorizationError(w, err)
				return
			}
			ctx := context.WithValue(r.Context(), orgIDKey, actor.OrgID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
