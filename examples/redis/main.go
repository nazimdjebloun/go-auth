// Command redis runs a local Redis-backed authentication API with SQL authority.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/redis/go-redis/v9"
	_ "modernc.org/sqlite"
)

func run(ctx context.Context) error {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "file:redis-example.db?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}
	client := redis.NewClient(&redis.Options{Addr: addr, ContextTimeoutEnabled: true, MaxRetries: -1, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, PoolTimeout: time.Second})
	defer func() { _ = client.Close() }()
	cfg, err := goauth.NewConfig(
		goauth.WithApp(goauth.AppConfig{Name: "Redis example", BaseURL: "http://localhost:8083", Environment: goauth.EnvironmentDev, Database: goauth.DatabaseConfig{Driver: goauth.DriverSQLite, URL: dsn}}),
		goauth.WithSecret(os.Getenv("GOAUTH_SECRET")),
		goauth.WithAuthentication(goauth.AuthenticationConfig{EmailPassword: true}),
		goauth.WithRegistration(goauth.RegistrationConfig{EmailPassword: true, AllowPublic: true}),
		// Local API demonstration without email. Deployed administrators should
		// retain the default mandatory 2FA and configure a real mailer.
		goauth.WithTwoFactor(goauth.TwoFactorConfig{DisableAdminTwoFactor: true}),
		goauth.WithBrowser(goauth.BrowserConfig{APIURL: "http://localhost:8083", AllowedOrigins: []string{"http://localhost:8083"}}),
		goauth.WithRedis(goauth.RedisConfig{Client: client, Prefix: "redis-example:development"}),
	)
	if err != nil {
		return err
	}
	auth, err := goauth.New(cfg)
	if err != nil {
		return err
	}
	defer auth.Close()
	mux := http.NewServeMux()
	auth.Mount(mux)
	pattern := "GET /app/me"
	mux.Handle(pattern, auth.Protect(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(middleware.GetUserFromContext(r.Context()))
	})))
	server := &http.Server{Addr: "127.0.0.1:8083", Handler: auth.CORS(mux), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute}
	done := make(chan error, 1)
	go func() { done <- server.ListenAndServe() }()
	slog.Info("Redis example listening", "address", server.Addr)
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err = server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			<-done
			return err
		}
		<-done
		return nil
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx); err != nil {
		slog.Error("Redis example failed", "error", err)
		os.Exit(1)
	}
}
