package middleware

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/nazimdjebloun/go-auth/service"
)

func writeJSON(w http.ResponseWriter, status int, v any, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		if logger == nil {
			logger = slog.Default()
		}
		logger.Error("failed to encode JSON response",
			"error", err,
			"status", status,
		)
	}
}

// logRejectedRequest emits a structured log for a request the middleware stack
// refused. The rejection reason, request method, and path are always included;
// callers append request-specific attributes (e.g. the rejected origin or the
// affected user ID) via attrs.
func logRejectedRequest(r *http.Request, logger *slog.Logger, level slog.Level, msg, reason string, attrs ...slog.Attr) {
	if logger == nil {
		logger = slog.Default()
	}
	base := []slog.Attr{
		slog.String("reason", reason),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}
	logger.LogAttrs(r.Context(), level, msg, append(base, attrs...)...)
}

func setSessionCookie(w http.ResponseWriter, svc *service.SessionService, token string) {
	cfg := svc.Config()
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    token,
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   int(cfg.Duration.Seconds()),
	})
}

func setRefreshCookie(w http.ResponseWriter, svc *service.SessionService, token string) {
	if token == "" {
		return
	}
	cfg := svc.Config()
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.RefreshCookieName,
		Value:    token,
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   int(cfg.RefreshTTL.Seconds()),
	})
}
