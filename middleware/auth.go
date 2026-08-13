package middleware

import (
	"context"
	"errors"
	"log/slog"
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

func ContextWithSession(ctx context.Context, session *domain.Session) context.Context {
	return context.WithValue(ctx, ctxSession, session)
}

func AuthMiddleware(sessionSvc *service.SessionService, userRepo interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, user, rawToken := resolveSession(w, r, sessionSvc, userRepo, logger)
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
// Rejections are logged at a level reflecting how actionable they are: routine
// cases (missing cookie, expired session) at Debug/Info, and rejections of an
// otherwise-valid session (banned or deleted user) at Warn.
func resolveSession(w http.ResponseWriter, r *http.Request, sessionSvc *service.SessionService, userRepo interface {
	GetByID(ctx context.Context, id string) (*domain.User, error)
}, logger *slog.Logger) (*domain.Session, *domain.User, string) {
	cookie, err := r.Cookie(sessionSvc.Config().CookieName)
	if err != nil {
		// Debug: fires on every unauthenticated request, deliberately below default log level to avoid flooding — raise handler level to Debug to see these.
		logRejectedRequest(r, logger, slog.LevelDebug, "auth rejected", "missing session cookie")
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":   "session_expired",
			"message": "Missing session cookie",
		}, logger)
		return nil, nil, ""
	}

	session, err := sessionSvc.Validate(r.Context(), cookie.Value)
	if err != nil {
		if !errors.Is(err, domain.ErrSessionExpired) {
			logRejectedRequest(r, logger, slog.LevelInfo, "auth rejected", "invalid session")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": "Invalid session",
			}, logger)
			return nil, nil, ""
		}

		// Session expired — try transparent refresh before giving up.
		refreshCookie, rcErr := r.Cookie(sessionSvc.Config().RefreshCookieName)
		if rcErr != nil || refreshCookie.Value == "" {
			logRejectedRequest(r, logger, slog.LevelInfo, "auth rejected", "session expired without refresh cookie")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "session_expired",
				"message": "Session has expired",
			}, logger)
			return nil, nil, ""
		}

		refreshResult, refreshErr := sessionSvc.RefreshSession(r.Context(), refreshCookie.Value)
		if refreshErr != nil {
			// Warn: cannot distinguish "both cookies just expired" from "possible token replay", so default to visibility.
			logRejectedRequest(r, logger, slog.LevelWarn, "auth rejected", "session refresh failed")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "session_expired",
				"message": "Session has expired",
			}, logger)
			return nil, nil, ""
		}

		SetSessionCookie(w, sessionSvc.Config(), refreshResult.SessionToken)
		SetRefreshCookie(w, sessionSvc.Config(), refreshResult.RefreshToken)

		session = refreshResult.Session

		user, err := userRepo.GetByID(r.Context(), session.UserID)
		if err != nil || user == nil {
			logRejectedRequest(r, logger, slog.LevelWarn, "auth rejected", "user not found after refresh", slog.String("user_id", session.UserID))
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":   "unauthorized",
				"message": "User not found",
			}, logger)
			return nil, nil, ""
		}

		if user.IsBanned {
			logRejectedRequest(r, logger, slog.LevelWarn, "auth rejected", "user banned", slog.String("user_id", user.ID))
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":   "user_banned",
				"message": "This account has been banned",
			}, logger)
			return nil, nil, ""
		}

		return session, user, refreshResult.SessionToken
	}

	user, err := userRepo.GetByID(r.Context(), session.UserID)
	if err != nil || user == nil {
		logRejectedRequest(r, logger, slog.LevelWarn, "auth rejected", "user not found", slog.String("user_id", session.UserID))
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":   "unauthorized",
			"message": "User not found",
		}, logger)
		return nil, nil, ""
	}

	if user.IsBanned {
		logRejectedRequest(r, logger, slog.LevelWarn, "auth rejected", "user banned", slog.String("user_id", user.ID))
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":   "user_banned",
			"message": "This account has been banned",
		}, logger)
		return nil, nil, ""
	}

	return session, user, cookie.Value
}

func RequireRole(role domain.Role, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil || user.Role != role {
				attrs := []slog.Attr{}
				if user != nil {
					attrs = append(attrs, slog.String("user_id", user.ID))
				}
				logRejectedRequest(r, logger, slog.LevelWarn, "auth rejected", "insufficient permissions", attrs...)
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":   "forbidden",
					"message": "Insufficient permissions",
				}, logger)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
