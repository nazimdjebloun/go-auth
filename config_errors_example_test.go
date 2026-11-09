package goauth_test

import (
	"errors"
	"fmt"

	goauth "github.com/nazimdjebloun/go-auth"
)

func ExampleConfigError() {
	_, err := goauth.NewConfig(
		goauth.WithApp(goauth.AppConfig{
			Name: "example", BaseURL: "https://app.example.com",
			Database: goauth.DatabaseConfig{Driver: goauth.DriverPostgres, URL: "postgres://unused:1/example"},
		}),
		goauth.WithSecret("short"),
		goauth.WithBrowser(goauth.BrowserConfig{AllowedOrigins: []string{"https://app.example.com/path"}}),
		goauth.WithTwoFactor(goauth.TwoFactorConfig{DisableAdminTwoFactor: true}),
	)
	var failure *goauth.ConfigError
	if errors.As(err, &failure) {
		for _, issue := range failure.Issues {
			fmt.Println(issue.Field, issue.Code)
		}
	}
	// Output:
	// Browser.AllowedOrigins[0] invalid_value
	// Secret out_of_range
}
