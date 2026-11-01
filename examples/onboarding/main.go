// Command onboarding demonstrates a complete local browser authentication flow.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/middleware"
	_ "modernc.org/sqlite"
)

//go:embed index.html
var page string

func newApplication(dsn, baseURL, secret string, options ...goauth.Option) (*goauth.Auth, http.Handler, error) {
	cfg, err := goauth.NewConfig(append([]goauth.Option{
		goauth.WithApp(goauth.AppConfig{
			Name: "Onboarding", BaseURL: baseURL, Environment: goauth.EnvironmentDev,
			Database: goauth.DatabaseConfig{Driver: goauth.DriverSQLite, URL: dsn},
		}),
		goauth.WithSecret(secret),
		goauth.WithAuthentication(goauth.AuthenticationConfig{EmailPassword: true}),
		goauth.WithRegistration(goauth.RegistrationConfig{
			EmailPassword: true, AllowPublic: true, RequireEmailVerification: true,
		}),
		goauth.WithTwoFactor(goauth.TwoFactorConfig{RequireEmail2FA: true}),
		goauth.WithBrowser(goauth.BrowserConfig{APIURL: baseURL, AllowedOrigins: []string{baseURL}}),
	}, options...)...)
	if err != nil {
		return nil, nil, err
	}
	auth, err := goauth.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	mux := http.NewServeMux()
	auth.Mount(mux)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = fmt.Fprint(w, page)
	})
	pattern := "POST /app/hello"
	mux.Handle(pattern, auth.Protect(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := middleware.GetUserFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"message": "Protected request succeeded", "userId": user.ID})
	})))
	return auth, auth.CORS(mux), nil
}

func run(ctx context.Context) error {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "file:onboarding.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}
	auth, handler, err := newApplication(dsn, "http://localhost:8080", os.Getenv("GOAUTH_SECRET"))
	if err != nil {
		return err
	}
	defer auth.Close()
	server := &http.Server{Addr: "127.0.0.1:8080", Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.ListenAndServe() }()
	slog.Info("Open http://localhost:8080; development email codes appear in this terminal")
	select {
	case err := <-serveErrors:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			_ = server.Close()
			<-serveErrors
			return err
		}
		err := <-serveErrors
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("onboarding startup failed", "error", err)
		os.Exit(1)
	}
}
