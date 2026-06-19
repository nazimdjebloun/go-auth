package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/nazimdjebloun/go-auth/handler"
	"github.com/nazimdjebloun/go-auth/service"
)

func Authenticate(authService *service.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeUnauthorized(w, "Missing authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				writeUnauthorized(w, "Invalid authorization header")
				return
			}

			token := parts[1]
			user, session, err := authService.ValidateSession(r.Context(), token)
			if err != nil {
				writeUnauthorized(w, err.Message)
				return
			}

			ctx := context.WithValue(r.Context(), handler.CtxUserID, user.ID)
			ctx = context.WithValue(ctx, handler.CtxUserRole, string(user.Role))
			ctx = context.WithValue(ctx, handler.CtxSessionID, session.ID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := r.Context().Value(handler.CtxUserRole)
			if role == nil || role.(string) != "admin" {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":   "forbidden",
					"message": "Admin access required",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusUnauthorized, map[string]string{
		"error":   "unauthorized",
		"message": msg,
	})
}
