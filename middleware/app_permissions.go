package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/httperr"
)

// AppPermissionChecker delegates authoritative current-state evaluation to services.
type AppPermissionChecker interface {
	RequirePermission(context.Context, api.CheckAppPermissionInput) error
}

// ProtectedAppAdminChecker verifies the non-delegable administrator identity.
type ProtectedAppAdminChecker interface {
	RequireProtectedAdmin(context.Context, api.AppPermissionActor) error
}

// RequireProtectedAppAdmin protects provisioning and other administrator-only routes.
func RequireProtectedAppAdmin(checker ProtectedAppAdminChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil || (reflect.ValueOf(checker).Kind() == reflect.Pointer && reflect.ValueOf(checker).IsNil()) {
				writeAppAuthorizationError(w, domain.ErrAppPermissionsDisabled)
				return
			}
			user := GetUserFromContext(r.Context())
			if user == nil {
				writeAppAuthorizationError(w, domain.ErrForbidden)
				return
			}
			actor := api.AppPermissionActor{UserID: user.ID}
			if session := GetSessionFromContext(r.Context()); session != nil {
				actor.SessionID = session.ID
			}
			if err := checker.RequireProtectedAdmin(r.Context(), actor); err != nil {
				writeAppAuthorizationError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeAppAuthorizationError(w http.ResponseWriter, err error) {
	ae := domain.ErrInternal
	var authErr *domain.AuthError
	if errors.As(err, &authErr) {
		ae = authErr
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httperr.StatusFor(ae.Code))
	_ = json.NewEncoder(w).Encode(ae)
}

// RequireAppPermission never treats a disabled capability as an allow decision.
func RequireAppPermission(checker AppPermissionChecker, key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if checker == nil || (reflect.ValueOf(checker).Kind() == reflect.Pointer && reflect.ValueOf(checker).IsNil()) {
				writeAppAuthorizationError(w, domain.ErrAppPermissionsDisabled)
				return
			}
			user := GetUserFromContext(r.Context())
			if user == nil {
				writeAppAuthorizationError(w, domain.ErrForbidden)
				return
			}
			actor := api.AppPermissionActor{UserID: user.ID}
			if session := GetSessionFromContext(r.Context()); session != nil {
				actor.SessionID = session.ID
			}
			if err := checker.RequirePermission(r.Context(), api.CheckAppPermissionInput{Actor: actor, PermissionKey: key}); err != nil {
				writeAppAuthorizationError(w, err)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
