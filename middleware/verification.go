package middleware

import (
	"log/slog"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
)

// RequireVerifiedEmail restricts authenticated users until email verification
// completes. Run it after AuthMiddleware; verification and logout handlers must
// use authentication alone so an existing session can finish verification.
func RequireVerifiedEmail(required bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if required && user != nil && !user.IsVerified {
				writeJSON(w, http.StatusForbidden, map[string]string{
					"error":   domain.ErrEmailNotVerified.Code,
					"message": domain.ErrEmailNotVerified.Message,
				}, slog.Default())
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
