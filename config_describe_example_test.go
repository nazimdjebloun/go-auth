package goauth_test

import (
	"fmt"

	goauth "github.com/nazimdjebloun/go-auth"
)

func ExampleConfig_Describe() {
	cfg, err := goauth.NewConfig(
		goauth.WithApp(goauth.AppConfig{
			Name: "example", BaseURL: "https://app.example.com",
			Database: goauth.DatabaseConfig{
				Driver: goauth.DriverPostgres, URL: "postgres://unused:1/example",
			},
		}),
		goauth.WithSecret("example-only-secret-at-least-32-bytes"),
		goauth.WithBrowser(goauth.BrowserConfig{AllowedOrigins: []string{"https://app.example.com"}}),
		goauth.WithTwoFactor(goauth.TwoFactorConfig{DisableAdminTwoFactor: true}),
		goauth.WithSession(goauth.SessionConfig{GraceWindow: goauth.Duration(0)}),
	)
	if err != nil {
		panic(err)
	}
	// Inspection works without a reachable database and starts no workers.
	description, err := cfg.Describe()
	if err != nil {
		panic(err)
	}
	fmt.Println("Secure cookies:", description.Browser.Cookies.Secure)
	fmt.Println("Refresh grace:", description.Session.GraceWindow)
	fmt.Println("Rate-limit store:", description.RateLimit.Store)
	fmt.Println("Database source:", description.Database.Source)
	fmt.Println("Connection limit:", description.Database.URLLimits.MaxOpenConns)
	fmt.Println("Recovery worker enabled:", description.Background.RecoveryEmail)
	// Output:
	// Secure cookies: true
	// Refresh grace: 0s
	// Rate-limit store: memory
	// Database source: url
	// Connection limit: 25
	// Recovery worker enabled: false
}
