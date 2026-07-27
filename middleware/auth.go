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

func ContextWithUser(ctx context.Context, user *domain.User) context.Context {
	return context.WithValue(ctx, ctxUser, user)
}

func AuthMiddleware(sessionSvc *service.SessionService, userRepo interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, user, rawToken := resolveSession(w, r, sessionSvc, userRepo)
			if session == nil || user == nil {
				return
			}

			sessionSvc.Touch(r.Context(), rawToken, session.LastActiveAt)

			ctx := context.WithValue(r.Context(), ctxSession, session)
			ctx = context.WithValue(ctx, ctxUser, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolveSession attempts to validate the session cookie. If the session is
// expired, it transparently refreshes using the refresh cookie before giving up.
func resolveSession(w http.ResponseWriter, r *http.Request, sessionSvc *service.SessionService, userRepo interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}) (*domain.Session, *domain.User, string) {
	cookie, err := r.Cookie(sessionSvc.Config().CookieName)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":   "session_expired",
			"message": "Missing session cookie",
		})
		return nil, nil, ""
	}

	session, err := sessionSvc.Validate(r.Context(), cookie.Value)
	if err != nil {
		if !errors.Is(err, domain.ErrSessionExpired) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": "Invalid session",
			})
			return nil, nil, ""
		}

		// Session expired — try transparent refresh before giving up.
		refreshCookie, rcErr := r.Cookie(sessionSvc.Config().RefreshCookieName)
		if rcErr != nil || refreshCookie.Value == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "session_expired",
				"message": "Session has expired",
			})
			return nil, nil, ""
		}

		refreshedSession, newRawToken, newRefreshToken, refreshErr := sessionSvc.RefreshSession(r.Context(), refreshCookie.Value)
		if refreshErr != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "session_expired",
				"message": "Session has expired",
			})
			return nil, nil, ""
		}

		setSessionCookie(w, sessionSvc, newRawToken)
		setRefreshCookie(w, sessionSvc, newRefreshToken)

		session = refreshedSession

		user, err := userRepo.GetByID(r.Context(), session.UserID)
		if err != nil || user == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": "User not found",
			})
			return nil, nil, ""
		}

		if user.IsBanned {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":   "user_banned",
				"message": "This account has been banned",
			})
			return nil, nil, ""
		}

		return session, user, newRawToken
	}

	user, err := userRepo.GetByID(r.Context(), session.UserID)
	if err != nil || user == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":   "unauthorized",
			"message": "User not found",
		})
		return nil, nil, ""
	}

	if user.IsBanned {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":   "user_banned",
			"message": "This account has been banned",
		})
		return nil, nil, ""
	}

	return session, user, cookie.Value
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
