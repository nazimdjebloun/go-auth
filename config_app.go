package goauth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/url"
)

// Environment identifies the deployment environment.
type Environment string

// EnvironmentDev and the following values identify deployment environments.
const (
	EnvironmentDev     Environment = "dev"
	EnvironmentStaging Environment = "staging"
	EnvironmentProd    Environment = "prod"
)

func (e Environment) normalize() Environment {
	switch string(e) {
	case "development":
		return EnvironmentDev
	case "production":
		return EnvironmentProd
	default:
		return e
	}
}

// AppConfig groups the identity-level settings for the application instance.
type AppConfig struct {
	Name        string         // app name displayed in emails
	BaseURL     string         // frontend base URL for email links
	Database    DatabaseConfig // database connection
	Environment Environment    // deployment environment (dev, staging, prod)
}

// WithApp configures app-level identity settings.
func WithApp(cfg AppConfig) Option {
	return func(c *Config) {
		c.app = cfg
	}
}

// WithLogger sets the structured logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Config) {
		c.logger = logger
	}
}
func (c *Config) validateApp() []error {
	var errs []error
	if c.app.Name == "" {
		errs = append(errs, errors.New("app_name cannot be empty"))
	}
	if c.app.BaseURL == "" {
		errs = append(errs, errors.New("base_url is required"))
	} else if parsedURL, err := url.Parse(c.app.BaseURL); err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		errs = append(errs, errors.New("base_url must be a valid HTTP or HTTPS URL"))
	}
	switch c.app.Environment.normalize() {
	case EnvironmentDev, EnvironmentStaging, EnvironmentProd:
	default:
		errs = append(errs, fmt.Errorf("environment must be one of dev, staging, or prod, got %q", c.app.Environment))
	}
	return errs
}

func (c *Config) applyAppDefaults() {
	if c.app.Environment == "" {
		c.app.Environment = EnvironmentProd
	}
}
