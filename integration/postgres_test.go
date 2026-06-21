package integration_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func postgresConfig(dsn string, mailer port.Mailer) goauth.Config {
	return goauth.Config{
		AppName: "TestAppPG",
		Database: goauth.DatabaseConfig{
			DB:     nil, // set below after open
			Driver: goauth.DriverPostgres,
		},
		SessionTTL:         1 * time.Hour,
		TokenTTL:           1 * time.Hour,
		InviteTTL:          1 * time.Hour,
		VerificationCodeTTL: 1 * time.Hour,
		Mailer:             mailer,
	}
}

func TestPostgres_RegisterAndValidateSession(t *testing.T) {
	dsn := os.Getenv("GOAUTH_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_POSTGRES_DSN not set")
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mailer := &testMailer{}
	cfg := postgresConfig(dsn, mailer)
	cfg.Database.DB = db

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

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mailer := &testMailer{}
	cfg := postgresConfig(dsn, mailer)
	cfg.Database.DB = db

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
	resetToken := extractCodeAfter(body, "Your password reset code: ")
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
