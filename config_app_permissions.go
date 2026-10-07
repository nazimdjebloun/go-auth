package goauth

import (
	"errors"
	"regexp"
)

// AppPermissionsConfig opts into one application role per account. Definitions
// and grants are managed explicitly in SQL, never seeded during startup.
type AppPermissionsConfig struct {
	Enable               bool
	EnableManagementHTTP bool
	DefaultRoleSlug      string
}

// WithAppPermissions enables application authorization independently of organizations.
func WithAppPermissions(cfg AppPermissionsConfig) Option {
	return func(c *Config) { c.appPermissions = cfg }
}

func (c *Config) applyAppPermissionDefaults() {
	if c.appPermissions.DefaultRoleSlug == "" {
		c.appPermissions.DefaultRoleSlug = "user"
	}
}

var appRoleSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,79}$`)

func (c *Config) validateAppPermissions() []error {
	var errs []error
	if c.appPermissions.EnableManagementHTTP && !c.appPermissions.Enable {
		errs = append(errs, errors.New("app_permissions: management HTTP requires Enable"))
	}
	if c.appPermissions.DefaultRoleSlug != "" && (!appRoleSlugPattern.MatchString(c.appPermissions.DefaultRoleSlug) || c.appPermissions.DefaultRoleSlug == "admin") {
		errs = append(errs, errors.New("app_permissions: DefaultRoleSlug must be a canonical non-admin role slug"))
	}
	return errs
}
