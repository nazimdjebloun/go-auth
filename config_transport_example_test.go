package goauth_test

import (
	"context"
	"database/sql"
	"fmt"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/api"
	_ "modernc.org/sqlite"
)

func ExampleTransport_services() {
	ctx := context.Background()
	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		panic(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := goauth.Migrate(ctx, db, goauth.MigrationOptions{Driver: "sqlite"}); err != nil {
		panic(err)
	}
	cfg, err := goauth.NewConfig(
		goauth.WithTransport(goauth.TransportServices),
		goauth.WithApp(goauth.AppConfig{
			Name: "Backend", Database: goauth.DatabaseConfig{Driver: goauth.DriverSQLite, DB: db},
		}),
		goauth.WithSecret("example-only-secret-at-least-32-bytes"),
		goauth.WithRegistration(goauth.RegistrationConfig{EmailPassword: true, AllowPublic: true}),
		// This mail-free example explicitly opts out of administrator email MFA.
		// Configuring a mailer lets applications retain the default admin policy.
		goauth.WithTwoFactor(goauth.TwoFactorConfig{DisableAdminTwoFactor: true}),
	)
	if err != nil {
		panic(err)
	}
	auth, err := goauth.New(cfg)
	if err != nil {
		panic(err)
	}
	defer auth.Close()
	registered, err := auth.Register(ctx, api.RegisterInput{
		Email: "ada@example.com", Password: "Example-Password-123", Name: "Ada",
	})
	if err != nil {
		panic(err)
	}
	actor, err := auth.GetActor(ctx, registered.SessionToken)
	if err != nil {
		panic(err)
	}
	if err := auth.Account(actor).Profile.ChangeName(ctx, "Ada Byron"); err != nil {
		panic(err)
	}
	user, _, err := auth.GetSession(ctx, registered.SessionToken)
	if err != nil {
		panic(err)
	}
	fmt.Println("Transport:", auth.Describe().Transport)
	fmt.Println("Browser policy absent:", auth.Describe().Browser == nil)
	fmt.Println("Profile:", user.Name)
	// Output:
	// Transport: services
	// Browser policy absent: true
	// Profile: Ada Byron
}
