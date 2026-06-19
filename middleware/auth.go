package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/service"
)

type ctxKey string

const (
	ctxSession ctxKey = "session"
	ctxUser    ctxKey = "user"
)

func GetSessionFromContext(ctx context.Context) *domain.Session {
	v, _ := ctx.Value(ctxSession).(*domain.Session)
	return v
}

func GetUserFromContext(ctx context.Context) *domain.User {
	v, _ := ctx.Value(ctxUser).(*domain.User)
	return v
}

func AuthMiddleware(sessionSvc *service.SessionService, userRepo interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("goauth_session")
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error":   "unauthorized",
					"message": "Missing session cookie",
				})
				return
			}

			session, err := sessionSvc.Validate(r.Context(), cookie.Value)
			if err != nil {
				if errors.Is(err, domain.ErrSessionExpired) {
					writeJSON(w, http.StatusUnauthorized, map[string]string{
						"error":   "session_expired",
						"message": "Session has expired",
					})
					return
				}
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error":   "unauthorized",
					"message": "Invalid session",
				})
				return
			}

			user, err := userRepo.GetByID(r.Context(), session.UserID)
			if err != nil || user == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{
					"error":   "unauthorized",
					"message": "User not found",
				})
				return
			}

			if user.IsBanned {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":   "user_banned",
					"message": "This account has been banned",
				})
				return
			}

			ctx := context.WithValue(r.Context(), ctxSession, session)
			ctx = context.WithValue(ctx, ctxUser, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequireRole(role domain.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil || user.Role != role {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":   "forbidden",
					"message": "Insufficient permissions",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
