package middleware

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/nazimdjebloun/go-auth/service"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Failed to encode JSON: %v", err)
	}
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
