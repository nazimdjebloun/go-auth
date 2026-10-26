package goauth

import "errors"

// OrgPermissionsConfig enables organization-local custom roles and permissions.
type OrgPermissionsConfig struct {
	Enable               bool
	EnableManagementHTTP bool
}

// WithOrgPermissions is independent of app permissions and requires organizations.
func WithOrgPermissions(cfg OrgPermissionsConfig) Option {
	return func(c *Config) { c.orgPermissions = cfg }
}
func (c *Config) validateOrgPermissions() []error {
	var errs []error
	if c.orgPermissions.Enable && !c.organizations.Enable {
		errs = append(errs, errors.New("org_permissions: requires organizations"))
	}
	if c.orgPermissions.EnableManagementHTTP && !c.orgPermissions.Enable {
		errs = append(errs, errors.New("org_permissions: management HTTP requires Enable"))
	}
	return errs
}
