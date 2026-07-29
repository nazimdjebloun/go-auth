package integration_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

const testDBName = "goauth_test"

func postgresConfig(db *sql.DB, mailer port.Mailer) goauth.Config {
	cfg, err := goauth.NewConfig(
		goauth.WithApp(goauth.AppConfig{
			Name:    "TestAppPG",
			BaseURL: "http://localhost:8080",
			Database: goauth.DatabaseConfig{
				DB:     db,
				Driver: goauth.DriverPostgres,
			},
		}),
		goauth.WithSession(goauth.SessionConfig{
			TTL:     1 * time.Hour,
			IdleTTL: 1 * time.Hour,
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowedOrigins: []string{"http://localhost:8080"},
			TokenTTL:       1 * time.Hour,
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(mailer),
	)
	if err != nil {
		panic(err)
	}
	return cfg
}

// postgresTestDB creates a dedicated goauth_test_db database (isolated from the
// user's database), applies the schema, and returns a connection to it.
// The returned cleanup function drops the test database entirely.
func postgresTestDB(t *testing.T, dsn string) (*sql.DB, func()) {
	t.Helper()

	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("pgx.ParseConfig: %v", err)
	}

	origDB := connConfig.Config.Database

	// Connect to the user's database to create the test database.
	connConfig.Config.Database = origDB
	adminDB := stdlib.OpenDB(*connConfig)

	_, err = adminDB.Exec("CREATE DATABASE " + testDBName)
	if err != nil && !strings.Contains(err.Error(), "already exists") {
		adminDB.Close()
		t.Fatalf("CREATE DATABASE: %v", err)
	}
	adminDB.Close()

	// Connect to the test database.
	connConfig.Config.Database = testDBName
	testDB := stdlib.OpenDB(*connConfig)

	cleanup := func() {
		testDB.Close()
		// Connect back to the user's database to drop the test database.
		connConfig.Config.Database = origDB
		cleanupDB := stdlib.OpenDB(*connConfig)
		cleanupDB.Exec("DROP DATABASE IF EXISTS " + testDBName + " WITH (FORCE)")
		cleanupDB.Close()
	}

	return testDB, cleanup
}

func TestPostgres_RegisterAndValidateSession(t *testing.T) {
	dsn := os.Getenv("GOAUTH_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_POSTGRES_DSN not set")
	}

	db, cleanup := postgresTestDB(t, dsn)
	defer cleanup()

	mailer := &testMailer{}
	migrateDB(t, db, "postgres")
	cfg := postgresConfig(db, mailer)

	a, err := goauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	ctx := context.Background()

	// Register
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "alice@pg.test",
		Password: "V@lidPswd1",
		Name:     "Alice",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if res.SessionToken == "" {
		t.Fatal("session token missing after register")
	}

	// Validate session
	user, session, aerr := a.Services.Auth.ValidateSession(ctx, res.SessionToken)
	if aerr != nil {
		t.Fatal("ValidateSession:", aerr)
	}
	if user.ID != res.User.ID {
		t.Error("user ID mismatch")
	}
	if session.ID != res.Session.ID {
		t.Error("session ID mismatch")
	}

	// Session token hash in DB is SHA256, not raw
	var tokHash string
	if err := db.QueryRow("SELECT token_hash FROM sessions WHERE id = $1", session.ID).Scan(&tokHash); err != nil {
		t.Fatal(err)
	}
	if tokHash == res.SessionToken {
		t.Error("raw session token stored in DB")
	}
	if tokHash != sha256Hex(res.SessionToken) {
		t.Error("session token hash mismatch")
	}

	// Logout
	if aerr := a.Services.Auth.Logout(ctx, session.ID); aerr != nil {
		t.Fatal(aerr)
	}

	// Validate after logout should fail
	_, _, aerr = a.Services.Auth.ValidateSession(ctx, res.SessionToken)
	if aerr == nil {
		t.Error("expected error after session revoked")
	}
}

func TestPostgres_PasswordReset(t *testing.T) {
	dsn := os.Getenv("GOAUTH_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_POSTGRES_DSN not set")
	}

	db, cleanup := postgresTestDB(t, dsn)
	defer cleanup()

	mailer := &testMailer{}
	migrateDB(t, db, "postgres")
	cfg := postgresConfig(db, mailer)

	a, err := goauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	ctx := context.Background()

	// Register (admin email skips verified check for login)
	if _, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "admin@pg.test",
		Password: "V@lidPswd1",
		Name:     "Admin",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	// Forgot password
	if aerr := a.Services.Password.ForgotPassword(ctx, service.ForgotPasswordInput{
		Email: "admin@pg.test",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	body := mailer.lastBody()
	resetToken := extractTokenFromEmail(body)
	if resetToken == "" {
		t.Fatal("could not extract reset token from email")
	}

	// Reset password
	if aerr := a.Services.Password.ResetPassword(ctx, service.ResetPasswordInput{
		Code:        resetToken,
		NewPassword: "NewP@sswd2",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	// Login with new password
	if _, aerr := a.Services.Auth.Login(ctx, service.LoginInput{
		Email:    "admin@pg.test",
		Password: "NewP@sswd2",
	}); aerr != nil {
		t.Fatal("login with new password failed:", aerr)
	}
}
